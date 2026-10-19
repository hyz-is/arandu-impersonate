// Package impersonate is an Arandu module that lets an impersonator -- the
// platform's manager -- take a user's place without signing out of their own
// account, act there as the user, and leave again, as laravel-impersonate does.
// The visit is held to a deadline, routes the application marks sensitive are
// protected while it lasts, and everything is recorded in arandu-activitylog
// under the impersonator's name.
//
//	module.go   -> registration, routes, handlers, the guard and the migration
//	config.go   -> what the application passes in
//	model.go    -> the impersonation
//	policy.go   -> who may go into which account
//	service.go  -> going in, coming back, the deadline, the history
//
// The bar that tells the operator whose account they are in is drawn by the
// application's layout from hesape's view.Impersonation, which every page built
// with view.New answers; its button posts to the route named impersonate.leave,
// which this module registers.
package impersonate

import (
	"context"
	"errors"
	stdhttp "net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/arandu-io/framework/data"
	"github.com/arandu-io/framework/foundation"
	fhttp "github.com/arandu-io/framework/http"
	"github.com/arandu-io/framework/http/middleware"
	"github.com/arandu-io/framework/security"
	"github.com/arandu-io/hesape/auth"
	"github.com/arandu-io/hesape/database/migrations"
	"github.com/arandu-io/hesape/database/schema"
)

// Module is what the application registers.
type Module struct {
	cfg      Config
	svc      *ImpersonateService
	sessions *security.SessionStore
}

// Compile-time proof that the module honors the contracts it claims.
var (
	_ foundation.Module     = (*Module)(nil)
	_ foundation.Migratable = (*Module)(nil)
)

// New returns the module, or the reason it cannot be built.
func New(cfg Config, db *data.DB, sessions *security.SessionStore) (*Module, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if db == nil {
		return nil, errors.New("impersonate: New needs a database handle: the impersonations are kept in a table")
	}
	if sessions == nil {
		return nil, errors.New("impersonate: New needs the session store: going into an account and back is a change of the session's subject")
	}
	cfg = cfg.withDefaults()
	svc := NewImpersonateService(db)
	svc.targets, svc.activity, svc.ttl, svc.userType = cfg.Targets, cfg.Activity, cfg.TTL, cfg.UserType
	svc.allowed, svc.requireReason = cfg.CanBeImpersonated, cfg.RequireReason
	return &Module{cfg: cfg, svc: svc, sessions: sessions}, nil
}

// Service is the use cases, for an application that calls them from its own
// code. Every method asks the policy.
func (m *Module) Service() *ImpersonateService { return m.svc }

// Name is the module identifier.
func (m *Module) Name() string { return "impersonate" }

// Routes registers the module's routes, behind RequireAuth and then the
// application's Config.Middleware.
//
// impersonate.leave is the name hesape's view.New links the way back by, so the
// bar every page draws posts here without the application spelling the path.
func (m *Module) Routes(r *fhttp.Router) {
	guards := []fhttp.Middleware{middleware.RequireAuth(m.sessions)}
	for _, mw := range m.cfg.Middleware {
		guards = append(guards, mw)
	}
	r = r.Group("", guards...)

	r.Action(stdhttp.MethodPost, m.cfg.Prefix+"/take/{id}", m.start).Name("impersonate")
	r.Action(stdhttp.MethodPost, m.cfg.Prefix+"/leave", m.leave).Name("impersonate.leave")
	r.Action(stdhttp.MethodGet, m.cfg.Prefix+"/history", m.history).Name("impersonate.history")
}

// start takes the operator into the account named in the path, and lands them
// inside it.
func (m *Module) start(ctx *fhttp.Context) error {
	who, _ := ctx.User()
	// A refused reason is validation.Errors: a page goes back with the
	// message on the field, a client that wants JSON gets 422.
	acting, record, err := m.svc.Take(ctx.Ctx(), who, ctx.Param("id"), ctx.Request.PostFormValue("reason"))
	if err != nil {
		return err
	}
	if _, err := m.sessions.Rotate(ctx.Ctx(), ctx.Response, m.sessions.IDFromRequest(ctx.Request), acting); err != nil {
		return err
	}
	if ctx.WantsJSON() {
		return ctx.JSON(stdhttp.StatusCreated, impersonationResource{record})
	}
	return ctx.Redirect(m.cfg.TakeRedirectTo)
}

// leave takes the operator back to their own account.
func (m *Module) leave(ctx *fhttp.Context) error {
	who, _ := ctx.User()
	back, record, err := m.svc.Leave(ctx.Ctx(), who, EndLeft)
	if err != nil {
		return err
	}
	if _, err := m.sessions.Rotate(ctx.Ctx(), ctx.Response, m.sessions.IDFromRequest(ctx.Request), back); err != nil {
		return err
	}
	if ctx.WantsJSON() {
		return ctx.JSON(stdhttp.StatusOK, impersonationResource{record})
	}
	return ctx.Redirect(m.cfg.LeaveRedirectTo)
}

// history answers a page of impersonations, for an operator.
func (m *Module) history(ctx *fhttp.Context) error {
	page, _ := strconv.Atoi(ctx.Query("page"))
	who, _ := ctx.User()
	rows, total, err := m.svc.History(ctx.Ctx(), who, HistoryQuery{
		ActorID: ctx.Query("actor"), TargetID: ctx.Query("target"), Status: Status(ctx.Query("status")), Page: page,
	})
	if err != nil {
		return err
	}
	return ctx.JSON(stdhttp.StatusOK, historyResource{rows: rows, total: total})
}

// Guard ends an impersonation whose deadline passed: the next request of the
// operator inside the account is taken back to their own, and the end is
// recorded. The application mounts it after RequireAuth on the routes an
// operator can reach from inside an account -- its panel, usually:
//
//	panel := r.Group("/painel", middleware.RequireAuth(sessions), impersonateModule.Guard())
func (m *Module) Guard() func(stdhttp.Handler) stdhttp.Handler {
	return func(next stdhttp.Handler) stdhttp.Handler {
		return stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
			current, ok := auth.SubjectFrom(r.Context())
			if !ok || current.Impersonator == nil {
				next.ServeHTTP(w, r)
				return
			}
			lapsed, err := m.svc.Lapsed(r.Context(), current)
			if err != nil || !lapsed {
				next.ServeHTTP(w, r)
				return
			}
			back, _, err := m.svc.Leave(r.Context(), current, EndExpired)
			if err != nil {
				stdhttp.Error(w, stdhttp.StatusText(stdhttp.StatusForbidden), stdhttp.StatusForbidden)
				return
			}
			if _, err := m.sessions.Rotate(r.Context(), w, m.sessions.IDFromRequest(r), back); err != nil {
				stdhttp.Error(w, stdhttp.StatusText(stdhttp.StatusInternalServerError), stdhttp.StatusInternalServerError)
				return
			}
			stdhttp.Redirect(w, r, m.cfg.LeaveRedirectTo, stdhttp.StatusSeeOther)
		})
	}
}

// Protect refuses a route to somebody impersonating -- laravel-impersonate's
// ProtectFromImpersonation. The application mounts it on what only the real
// owner may do even when the impersonator acts as them: changing the password
// or the e-mail, the two factors, deleting the account, paying. A browser is
// sent back where it came from, a client that asks for JSON is answered 403.
//
//	r.Group("/painel/seguranca", middleware.RequireAuth(sessions), impersonateModule.Protect())
func (m *Module) Protect() func(stdhttp.Handler) stdhttp.Handler {
	return func(next stdhttp.Handler) stdhttp.Handler {
		return stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
			current, ok := auth.SubjectFrom(r.Context())
			if !ok || current.Impersonator == nil {
				next.ServeHTTP(w, r)
				return
			}
			if wantsJSON(r) {
				stdhttp.Error(w, stdhttp.StatusText(stdhttp.StatusForbidden), stdhttp.StatusForbidden)
				return
			}
			stdhttp.Redirect(w, r, m.back(r), stdhttp.StatusSeeOther)
		})
	}
}

// back is where a refused browser returns: the page it came from when that
// page is on this site, the landing inside the account otherwise.
func (m *Module) back(r *stdhttp.Request) string {
	referer, err := url.Parse(r.Referer())
	if err != nil || referer.Path == "" || (referer.Host != "" && referer.Host != r.Host) || referer.Path == r.URL.Path {
		return m.cfg.TakeRedirectTo
	}
	if referer.RawQuery != "" {
		return referer.Path + "?" + referer.RawQuery
	}
	return referer.Path
}

// wantsJSON is a client that asks for JSON rather than a page.
func wantsJSON(r *stdhttp.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "application/json") && !strings.Contains(r.Header.Get("Accept"), "text/html")
}

// impersonationResource is one impersonation as a response says it.
type impersonationResource struct{ i *Impersonation }

func impersonationFields(i *Impersonation) map[string]any {
	if i == nil {
		return map[string]any{}
	}
	out := map[string]any{
		"id": i.ID, "actor_id": i.ActorID, "target_id": i.TargetID, "acting": bool(i.Acting),
		"status": string(i.Status), "started_at": i.StartedAt.UTC().Format(time.RFC3339),
		"expires_at": i.ExpiresAt.UTC().Format(time.RFC3339),
	}
	if i.Status == Closed {
		out["closed_at"], out["end_reason"] = i.ClosedAt.UTC().Format(time.RFC3339), i.EndReason
	}
	if i.Reason != "" {
		out["reason"] = i.Reason
	}
	return out
}

func (r impersonationResource) ToArray() map[string]any { return impersonationFields(r.i) }
func (r impersonationResource) With() map[string]any    { return nil }

type historyResource struct {
	rows  []*Impersonation
	total int
}

func (r historyResource) ToArray() map[string]any {
	items := make([]map[string]any, 0, len(r.rows))
	for _, i := range r.rows {
		items = append(items, impersonationFields(i))
	}
	return map[string]any{"items": items, "total": r.total}
}
func (r historyResource) With() map[string]any { return nil }

// Migrations declares the schema this module owns.
func (m *Module) Migrations() []foundation.Migration {
	return []foundation.Migration{createImpersonations{}, addReasonToImpersonations{}}
}

var _ migrations.ReversibleMigration = createImpersonations{}

// createImpersonations is the visits operators made to accounts.
type createImpersonations struct{ migrations.BaseMigration }

// GetName is the migration's identity, and it carries the order.
func (createImpersonations) GetName() string { return "20261013_0001_create_impersonations" }

// Up creates the table.
func (createImpersonations) Up(ctx context.Context, conn migrations.Connection) error {
	return conn.Schema().Create(ctx, impersonationsTable, func(table *schema.Blueprint) {
		table.String("id", maxIdentifierLen).Primary()
		table.String("tenant_id", maxIdentifierLen)
		table.String("actor_id", maxIdentifierLen)
		table.String("target_id", maxIdentifierLen)
		table.UnsignedSmallInteger("acting").Default(0)
		table.String("status", 16)
		table.Timestamp("started_at")
		table.Timestamp("expires_at")
		table.Timestamp("closed_at")
		table.String("end_reason", 16).Default("")
		table.Timestamp("created_at")
		table.Timestamp("updated_at")
		table.Index([]string{"tenant_id", "actor_id", "target_id", "status"}, "impersonations_open_idx")
		table.Index([]string{"tenant_id", "started_at", "id"}, "impersonations_started_idx")
	})
}

// Down drops the table.
func (createImpersonations) Down(ctx context.Context, conn migrations.Connection) error {
	return conn.Schema().DropIfExists(ctx, impersonationsTable)
}

var _ migrations.ReversibleMigration = addReasonToImpersonations{}

// addReasonToImpersonations keeps why the operator went in.
type addReasonToImpersonations struct{ migrations.BaseMigration }

// GetName is the migration's identity, and it carries the order.
func (addReasonToImpersonations) GetName() string {
	return "20261019_0001_add_reason_to_impersonations"
}

// Up adds the column, empty for the visits made before it.
func (addReasonToImpersonations) Up(ctx context.Context, conn migrations.Connection) error {
	return conn.Schema().Table(ctx, impersonationsTable, func(table *schema.Blueprint) {
		table.String("reason", MaxReasonLen*4).Default("")
	})
}

// Down drops the column.
func (addReasonToImpersonations) Down(ctx context.Context, conn migrations.Connection) error {
	return conn.Schema().Table(ctx, impersonationsTable, func(table *schema.Blueprint) {
		table.DropColumn("reason")
	})
}
