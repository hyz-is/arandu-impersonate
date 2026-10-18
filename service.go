package impersonate

import (
	"context"
	"fmt"
	"time"

	"github.com/arandu-io/framework/data"
	"github.com/arandu-io/framework/security"
	"github.com/arandu-io/hesape/auth"
	activitylog "github.com/hyz-is/arandu-activitylog"
)

const (
	defaultLimit = 50
	maxLimit     = 200
)

// The refusals of an impersonation the policy cannot see, because they are
// about the account and not the impersonation. Each wraps ErrForbidden.
var (
	// ErrNotImpersonable is an operator going into another operator's
	// account.
	ErrNotImpersonable = fmt.Errorf("impersonate: this account cannot be impersonated: %w", security.ErrForbidden)
	// ErrNotImpersonating is a leave asked by somebody who is in no account but
	// their own.
	ErrNotImpersonating = fmt.Errorf("impersonate: nobody is inside another account here: %w", security.ErrForbidden)
)

// ImpersonateService is the package's use cases. It owns the database handle;
// every exported method asks the policy before it reads or writes.
type ImpersonateService struct {
	db     *data.DB
	policy ImpersonatePolicy

	// now is the clock, replaceable by a test.
	now func() time.Time

	targets  Targets
	allowed  func(ctx context.Context, target security.Subject) bool
	activity *activitylog.Logger
	ttl      time.Duration
	userType string
}

// NewImpersonateService returns the use cases over a database handle. New wires
// the rest.
func NewImpersonateService(db *data.DB) *ImpersonateService {
	return &ImpersonateService{db: db, now: func() time.Time { return time.Now().UTC() }, ttl: DefaultTTL, userType: DefaultUserType}
}

// Start takes an operator into somebody's account: the answer is the subject
// the session carries from then on -- the account's owner, with the operator
// kept as the one acting, able to change it -- and the impersonation that
// records the visit.
//
// The operator may not go into their own account, into another operator's,
// or anywhere from inside an account already.
func (s *ImpersonateService) Take(ctx context.Context, actor security.Subject, targetID string) (security.Subject, *Impersonation, error) {
	g, err := security.Authorize(ctx, s.policy, actor, ImpersonateTake, Impersonation{})
	if err != nil {
		return security.Subject{}, nil, err
	}
	target, err := s.targets.Target(ctx, data.Tenant(g), targetID)
	if err != nil {
		return security.Subject{}, nil, err
	}
	if target.ID == "" {
		return security.Subject{}, nil, ErrNotFound
	}
	if target.Tenant != actor.Tenant {
		return security.Subject{}, nil, ErrNotFound
	}
	if IsOperator(target) || (s.allowed != nil && !s.allowed(ctx, target)) {
		return security.Subject{}, nil, ErrNotImpersonable
	}
	acting, err := auth.ImpersonateActing(actor, target)
	if err != nil {
		return security.Subject{}, nil, fmt.Errorf("%w: %w", security.ErrForbidden, err)
	}

	record, err := Impersonations(s.db).New()
	if err != nil {
		return security.Subject{}, nil, err
	}
	if record.ID, err = data.NewID(); err != nil {
		return security.Subject{}, nil, err
	}
	now := s.now()
	record.TenantID, record.ActorID, record.TargetID = data.Tenant(g), actor.ID, target.ID
	record.Acting, record.Status = true, Open
	record.StartedAt, record.ExpiresAt, record.ClosedAt = now, now.Add(s.ttl), now
	record.CreatedAt, record.UpdatedAt = now, now
	if _, err := record.Save(ctx, g); err != nil {
		return security.Subject{}, nil, err
	}
	if _, err := s.activity.In(ctx, g, LogName).Event("impersonation.taken").
		OnRef(activitylog.Ref{Type: s.userType, ID: target.ID}).
		WithProperty("impersonation", record.ID).WithProperty("expires_at", record.ExpiresAt.Format(time.RFC3339)).
		Log("entrou na conta para inspecionar"); err != nil {
		return security.Subject{}, nil, err
	}
	return acting, record, nil
}

// Leave takes the operator inside an account back to their own: the answer
// is the operator's own subject, for the session, and the impersonation it
// closed. reason is EndLeft or EndExpired.
func (s *ImpersonateService) Leave(ctx context.Context, current security.Subject, reason string) (security.Subject, *Impersonation, error) {
	if current.Impersonator == nil {
		return security.Subject{}, nil, ErrNotImpersonating
	}
	back, err := auth.Leave(current)
	if err != nil {
		return security.Subject{}, nil, fmt.Errorf("%w: %w", security.ErrForbidden, err)
	}
	g, err := security.Authorize(ctx, s.policy, back, ImpersonateLeave, Impersonation{})
	if err != nil {
		return security.Subject{}, nil, err
	}
	open, err := Impersonations(s.db).Where("actor_id", "=", back.ID).Where("target_id", "=", current.ID).
		Where("status", "=", string(Open)).OrderByDesc("started_at").First(ctx, g)
	if err != nil {
		return security.Subject{}, nil, err
	}
	if open == nil {
		// Nothing to close -- the deadline closed it, or the row is gone --
		// and the operator still goes back.
		return back, nil, nil
	}
	if _, err := security.Authorize(ctx, s.policy, back, ImpersonateLeave, *open); err != nil {
		return security.Subject{}, nil, err
	}
	if reason != EndExpired {
		reason = EndLeft
	}
	now := s.now()
	open.Status, open.ClosedAt, open.EndReason, open.UpdatedAt = Closed, now, reason, now
	if _, err := open.Save(ctx, g); err != nil {
		return security.Subject{}, nil, err
	}
	description := "saiu da conta inspecionada"
	if reason == EndExpired {
		description = "a inspeção da conta expirou"
	}
	if _, err := s.activity.In(ctx, g, LogName).Event("impersonation."+reason).
		OnRef(activitylog.Ref{Type: s.userType, ID: current.ID}).
		WithProperty("impersonation", open.ID).Log(description); err != nil {
		return security.Subject{}, nil, err
	}
	return back, open, nil
}

// Lapsed reports whether the impersonation the current subject is in has passed
// its deadline, or no longer exists as open. A subject that is in no
// impersonation has nothing lapsed.
func (s *ImpersonateService) Lapsed(ctx context.Context, current security.Subject) (bool, error) {
	if current.Impersonator == nil {
		return false, nil
	}
	back := *current.Impersonator
	g, err := security.Authorize(ctx, s.policy, back, ImpersonateLeave, Impersonation{})
	if err != nil {
		return false, err
	}
	open, err := Impersonations(s.db).Where("actor_id", "=", back.ID).Where("target_id", "=", current.ID).
		Where("status", "=", string(Open)).OrderByDesc("started_at").First(ctx, g)
	if err != nil {
		return false, err
	}
	return open == nil || open.Expired(s.now()), nil
}

// HistoryQuery narrows the history. Page counts from one.
type HistoryQuery struct {
	ActorID  string
	TargetID string
	Status   Status
	Page     int
	PerPage  int
}

// History is a page of impersonations, newest first, and how many there are.
func (s *ImpersonateService) History(ctx context.Context, actor security.Subject, q HistoryQuery) ([]*Impersonation, int, error) {
	g, err := security.Authorize(ctx, s.policy, actor, ImpersonateHistory, Impersonation{})
	if err != nil {
		return nil, 0, err
	}
	if q.PerPage <= 0 || q.PerPage > maxLimit {
		q.PerPage = defaultLimit
	}
	if q.Page < 1 {
		q.Page = 1
	}
	filtered := func() *ImpersonationQuery {
		b := Impersonations(s.db)
		if q.ActorID != "" {
			b = b.Where("actor_id", "=", q.ActorID)
		}
		if q.TargetID != "" {
			b = b.Where("target_id", "=", q.TargetID)
		}
		if q.Status != "" {
			b = b.Where("status", "=", string(q.Status))
		}
		return b
	}
	total, err := filtered().Count(ctx, g)
	if err != nil {
		return nil, 0, err
	}
	rows, err := filtered().OrderByDesc("started_at").OrderByDesc("id").Offset((q.Page-1)*q.PerPage).Limit(q.PerPage).Get(ctx, g)
	if err != nil {
		return nil, 0, err
	}
	return rows, int(total), nil
}

// Find answers one impersonation, for an operator.
func (s *ImpersonateService) Find(ctx context.Context, actor security.Subject, id string) (*Impersonation, error) {
	g, err := security.Authorize(ctx, s.policy, actor, ImpersonateHistory, Impersonation{})
	if err != nil {
		return nil, err
	}
	record, err := Impersonations(s.db).WhereKey(id).First(ctx, g)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, ErrNotFound
	}
	if _, err := security.Authorize(ctx, s.policy, actor, ImpersonateHistory, *record); err != nil {
		return nil, err
	}
	return record, nil
}

// OpenNow lists the impersonations under way: who is inside which account right
// now, and until when.
func (s *ImpersonateService) OpenNow(ctx context.Context, actor security.Subject) ([]*Impersonation, error) {
	g, err := security.Authorize(ctx, s.policy, actor, ImpersonateHistory, Impersonation{})
	if err != nil {
		return nil, err
	}
	return Impersonations(s.db).Where("status", "=", string(Open)).OrderByDesc("started_at").Limit(maxLimit).Get(ctx, g)
}
