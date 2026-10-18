package unit_test

import (
	"context"
	"errors"
	"testing"

	"github.com/arandu-io/framework/data"
	"github.com/arandu-io/framework/security"
	"github.com/arandu-io/hesape/auth"
	"github.com/arandu-io/hesape/database/model"

	impersonate "github.com/hyz-is/arandu-impersonate"
)

// operator is the subject the application gave the inspecting role.
func operator() security.Subject {
	return security.Subject{ID: "op-1", Tenant: "acme", Roles: []string{impersonate.ImpersonatorRole}, Verified: true}
}

// member is a signed-in person with no role of this package.
func member() security.Subject {
	return security.Subject{ID: "user-1", Tenant: "acme", Roles: []string{"admin"}, Verified: true}
}

func TestOnlyAnOperatorGoesIntoAccountsAndReadsTheHistory(t *testing.T) {
	t.Parallel()

	for _, action := range []security.Action{impersonate.ImpersonateTake, impersonate.ImpersonateHistory} {
		if _, err := security.Authorize(context.Background(), impersonate.ImpersonatePolicy{}, operator(), action, impersonate.Impersonation{}); err != nil {
			t.Errorf("an operator was refused %s: %v", action, err)
		}
		// A role named "admin" is the application's, not this package's.
		if _, err := security.Authorize(context.Background(), impersonate.ImpersonatePolicy{}, member(), action, impersonate.Impersonation{}); !errors.Is(err, security.ErrForbidden) {
			t.Errorf("a member was allowed %s: %v", action, err)
		}
		if _, err := security.Authorize(context.Background(), impersonate.ImpersonatePolicy{}, security.Guest("acme"), action, impersonate.Impersonation{}); !errors.Is(err, security.ErrForbidden) {
			t.Errorf("a guest was allowed %s: %v", action, err)
		}
	}
}

// TestAnOperatorWhosePermissionsAreAdministeredHoldsTheActions holds the
// shape arandu-permission gives a subject: Actions filled, Roles left alone.
func TestAnOperatorWhosePermissionsAreAdministeredHoldsTheActions(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	both := security.Subject{ID: "op-9", Tenant: "acme", Verified: true,
		Actions: []security.Action{impersonate.ImpersonateTake, impersonate.ImpersonateHistory}}
	for _, action := range []security.Action{impersonate.ImpersonateTake, impersonate.ImpersonateHistory} {
		if _, err := security.Authorize(ctx, impersonate.ImpersonatePolicy{}, both, action, impersonate.Impersonation{}); err != nil {
			t.Errorf("a subject holding the actions was refused %s: %v", action, err)
		}
	}
	if got := impersonate.Actions(); len(got) != 2 || got[0] != impersonate.ImpersonateTake || got[1] != impersonate.ImpersonateHistory {
		t.Errorf("Actions() = %v, want the two an application grants", got)
	}
	if !impersonate.IsOperator(both) || !impersonate.IsOperator(operator()) || impersonate.IsOperator(member()) {
		t.Error("IsOperator does not answer the role and the action")
	}

	// Each action opens itself and nothing else.
	takes := security.Subject{ID: "op-9", Tenant: "acme", Verified: true, Actions: []security.Action{impersonate.ImpersonateTake}}
	if _, err := security.Authorize(ctx, impersonate.ImpersonatePolicy{}, takes, impersonate.ImpersonateTake, impersonate.Impersonation{}); err != nil {
		t.Errorf("a subject holding %s was refused it: %v", impersonate.ImpersonateTake, err)
	}
	if _, err := security.Authorize(ctx, impersonate.ImpersonatePolicy{}, takes, impersonate.ImpersonateHistory, impersonate.Impersonation{}); !errors.Is(err, security.ErrForbidden) {
		t.Errorf("%s opened %s: %v", impersonate.ImpersonateTake, impersonate.ImpersonateHistory, err)
	}
	// An action of another package, or one spelled like a role, opens nothing.
	unrelated := security.Subject{ID: "user-1", Tenant: "acme", Verified: true,
		Actions: []security.Action{"user.view", security.Action(impersonate.ImpersonatorRole)}}
	for _, action := range []security.Action{impersonate.ImpersonateTake, impersonate.ImpersonateHistory} {
		if _, err := security.Authorize(ctx, impersonate.ImpersonatePolicy{}, unrelated, action, impersonate.Impersonation{}); !errors.Is(err, security.ErrForbidden) {
			t.Errorf("an unrelated action allowed %s: %v", action, err)
		}
	}
	// Inside an account the actions open nothing either.
	inside, err := auth.ImpersonateActing(both, member())
	if err != nil {
		t.Fatal(err)
	}
	inside.Actions = append(inside.Actions, impersonate.ImpersonateTake, impersonate.ImpersonateHistory)
	for _, action := range []security.Action{impersonate.ImpersonateTake, impersonate.ImpersonateHistory} {
		if _, err := security.Authorize(ctx, impersonate.ImpersonatePolicy{}, inside, action, impersonate.Impersonation{}); !errors.Is(err, security.ErrForbidden) {
			t.Errorf("a subject inside an account was allowed %s by the action: %v", action, err)
		}
	}
	// And another tenant's record stays another tenant's.
	foreign := impersonate.Impersonation{ID: "i-1", TenantID: "globex", ActorID: "op-9"}
	if _, err := security.Authorize(ctx, impersonate.ImpersonatePolicy{}, both, impersonate.ImpersonateHistory, foreign); !errors.Is(err, security.ErrForbidden) {
		t.Errorf("the action read another tenant's impersonation: %v", err)
	}
}

func TestNobodyGoesAnywhereFromInsideAnAccount(t *testing.T) {
	t.Parallel()

	inside, err := auth.ImpersonateActing(operator(), member())
	if err != nil {
		t.Fatal(err)
	}
	// Even with the operator's role on the account, which an operator
	// account is refused to begin with.
	inside.Roles = append(inside.Roles, impersonate.ImpersonatorRole)
	for _, action := range []security.Action{impersonate.ImpersonateTake, impersonate.ImpersonateHistory, impersonate.ImpersonateLeave} {
		if _, err := security.Authorize(context.Background(), impersonate.ImpersonatePolicy{}, inside, action, impersonate.Impersonation{}); !errors.Is(err, security.ErrForbidden) {
			t.Errorf("a subject inside an account was allowed %s: %v", action, err)
		}
	}
}

func TestTheOperatorWhoOpenedAnImpersonationClosesIt(t *testing.T) {
	t.Parallel()

	opened := impersonate.Impersonation{ID: "i-1", TenantID: "acme", ActorID: "op-1", TargetID: "user-1"}
	// The operator, back as themselves, without the role any more.
	plain := operator()
	plain.Roles = nil
	if _, err := security.Authorize(context.Background(), impersonate.ImpersonatePolicy{}, plain, impersonate.ImpersonateLeave, opened); err != nil {
		t.Fatalf("the operator was refused closing their own impersonation: %v", err)
	}
	other := security.Subject{ID: "op-2", Tenant: "acme", Roles: []string{impersonate.ImpersonatorRole}, Verified: true}
	if _, err := security.Authorize(context.Background(), impersonate.ImpersonatePolicy{}, other, impersonate.ImpersonateLeave, opened); !errors.Is(err, security.ErrForbidden) {
		t.Fatalf("another operator closed it: %v", err)
	}
	foreign := opened
	foreign.TenantID = "globex"
	if _, err := security.Authorize(context.Background(), impersonate.ImpersonatePolicy{}, operator(), impersonate.ImpersonateLeave, foreign); !errors.Is(err, security.ErrForbidden) {
		t.Fatalf("an impersonation of another tenant was closed: %v", err)
	}
}

// nilHandle is a handle over no database: any statement panics.
func nilHandle() *data.DB { return data.Wrap(nil, data.DialectSQLite) }

func TestTheServiceRefusesBeforeReachingTheModel(t *testing.T) {
	t.Parallel()

	service := impersonate.NewImpersonateService(nil)
	ctx := context.Background()
	if _, _, err := service.Take(ctx, member(), "user-2"); !errors.Is(err, security.ErrForbidden) {
		t.Fatalf("Start reached the Model before the policy refusal: %v", err)
	}
	if _, _, err := service.History(ctx, member(), impersonate.HistoryQuery{}); !errors.Is(err, security.ErrForbidden) {
		t.Fatalf("History reached the Model before the policy refusal: %v", err)
	}
	if _, err := service.Find(ctx, member(), "i-1"); !errors.Is(err, security.ErrForbidden) {
		t.Fatalf("Find reached the Model before the policy refusal: %v", err)
	}
	if _, err := service.OpenNow(ctx, member()); !errors.Is(err, security.ErrForbidden) {
		t.Fatalf("OpenNow reached the Model before the policy refusal: %v", err)
	}
	if _, _, err := service.Leave(ctx, member(), impersonate.EndLeft); !errors.Is(err, impersonate.ErrNotImpersonating) {
		t.Fatalf("Leave outside an impersonation answered %v", err)
	}
	if lapsed, err := service.Lapsed(ctx, member()); err != nil || lapsed {
		t.Fatalf("an ordinary session lapsed: %v, %v", lapsed, err)
	}
}

func TestTheMissingRecordIsTheModelsNotFound(t *testing.T) {
	t.Parallel()

	if !errors.Is(impersonate.ErrNotFound, model.ErrModelNotFound) {
		t.Fatal("ErrNotFound does not wrap model.ErrModelNotFound")
	}
}

func TestASystemGrantWithoutATenantReachesNothing(t *testing.T) {
	t.Parallel()

	_, err := impersonate.Impersonations(nilHandle()).WhereKey("i-1").First(context.Background(), security.SystemGrant(impersonate.ImpersonateHistory, ""))
	if !errors.Is(err, model.ErrNoTenant) {
		t.Fatalf("a system grant with no tenant returned %v, want ErrNoTenant", err)
	}
}
