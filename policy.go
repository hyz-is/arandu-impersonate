package impersonate

import (
	"context"
	"fmt"

	"github.com/arandu-io/framework/security"
)

// The actions of the package. Constants rather than strings at the call site:
// a typo in an action name would silently authorize nothing, or worse,
// everything.
const (
	// ImpersonateTake is an operator going into somebody's account.
	ImpersonateTake security.Action = "impersonate"
	// ImpersonateLeave is the operator going back to their own account.
	ImpersonateLeave security.Action = "impersonate.leave"
	// ImpersonateHistory is reading who went into which account, and when.
	ImpersonateHistory security.Action = "impersonate.history"
)

// ImpersonatorRole is the role that may go into other people's accounts and read
// the history. The application gives it through arandu-permission, which
// fills the Subject's roles.
const ImpersonatorRole = "impersonate.impersonator"

// ImpersonatePolicy is the only authority over who goes into whose account.
//
// It denies unless a rule below allows. An operator goes into accounts of
// their own tenant and reads its history; whoever an impersonation names as its
// operator ends it. Whether the account itself may be gone into -- another
// operator's, the operator's own -- is the service's refusal, because the
// policy sees the impersonation and not the account.
type ImpersonatePolicy struct{}

// Compile-time proof that the policy answers about this entity and no other.
var _ security.Policy[Impersonation] = ImpersonatePolicy{}

// Can decides whether the subject may perform the action on the record.
func (ImpersonatePolicy) Can(ctx context.Context, s security.Subject, a security.Action, record Impersonation) error {
	// Tenant isolation comes first and applies to every action. The empty id
	// is the probe a listing asks, or the impersonation about to begin.
	if record.ID != "" && record.TenantID != s.Tenant {
		return fmt.Errorf("impersonation belongs to another tenant")
	}

	// arandu:begin custom

	if s.IsGuest() {
		return fmt.Errorf("a guest inspects nobody")
	}
	// Somebody already inside an account goes nowhere else from there.
	if s.Impersonator != nil {
		return fmt.Errorf("%s is inside %s's account", s.Impersonator.ID, s.ID)
	}

	switch a {
	case ImpersonateTake, ImpersonateHistory:
		if s.HasRole(ImpersonatorRole) {
			return nil
		}
	case ImpersonateLeave:
		// The operator, back as themselves, closes what they opened. The
		// role is not asked: an operator whose role was taken away while
		// inside still has to be able to leave.
		if record.ID == "" || record.ActorID == s.ID {
			return nil
		}
	}

	// arandu:end custom

	return fmt.Errorf("no rule allows %s on impersonation", a)
}
