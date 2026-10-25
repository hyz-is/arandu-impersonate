package impersonate

import (
	"context"
	"fmt"

	"github.com/arandu-io/framework/security"
	"github.com/arandu-io/hesape/auth"
)

// The actions of the package. Constants rather than strings at the call site:
// a typo in an action name would silently authorize nothing, or worse,
// everything.
const (
	// ImpersonateTake is an operator going into somebody's account.
	ImpersonateTake security.Action = "impersonate.take"
	// ImpersonateLeave is the operator going back to their own account.
	ImpersonateLeave security.Action = "impersonate.leave"
	// ImpersonateHistory is reading who went into which account, and when.
	ImpersonateHistory security.Action = "impersonate.history"
)

// ImpersonatorRole is the role that may go into other people's accounts and read
// the history, for an application that decides by role and fills the
// Subject's Roles itself.
//
// An application whose permissions are administered by arandu-permission
// grants the actions instead: arandu-permission fills the Subject's Actions
// and never its Roles, so ImpersonateTake and ImpersonateHistory are what its
// platform managers' group holds. The policy accepts either, and an account
// that holds the role or ImpersonateTake is an operator's, never impersonated.
const ImpersonatorRole = "impersonate.impersonator"

// Actions are the actions an application grants through arandu-permission,
// spliced into its permission.Config.Actions. ImpersonateLeave is not one of
// them: nobody is granted leaving, the operator who went in always may.
func Actions() []security.Action { return []security.Action{ImpersonateTake, ImpersonateHistory} }

// IsOperator reports whether the subject may go into other people's accounts:
// it carries ImpersonatorRole, or holds the action ImpersonateTake. Such an
// account is never impersonated itself.
func IsOperator(s security.Subject) bool {
	return s.HasRole(ImpersonatorRole) || s.Can(ImpersonateTake)
}

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

// Compile-time proof that the policy says which of its actions write: without
// it the Grant issued to read the history would also be one that writes.
var _ auth.Writes = ImpersonatePolicy{}

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
		// The role, for an application that decides by role; the action
		// itself, for one whose permissions arandu-permission administers.
		if s.HasRole(ImpersonatorRole) || s.Can(a) {
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

// Writes reports whether a Grant issued for the action may change anything.
//
// Going in and coming back write the impersonation; everything else reads, so
// the Grant issued to read the history cannot insert, update or delete a row
// whatever the code holding it does next, and an action added without a
// decision here fails the first time it tries to write.
func (ImpersonatePolicy) Writes(a security.Action) bool {
	switch a {
	case ImpersonateTake, ImpersonateLeave:
		return true
	}
	return false
}
