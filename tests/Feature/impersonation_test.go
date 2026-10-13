package feature_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/arandu-io/framework/security"

	impersonate "github.com/hyz-is/arandu-impersonate"
)

func TestAnOperatorGoesIntoAnAccountActsThereAndComesBack(t *testing.T) {
	w := install(t)
	cookies := w.signIn(t, "op-1")

	rec, cookies := w.do(t, http.MethodPost, impersonate.DefaultPrefix+"/take/ana", cookies)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/painel" {
		t.Fatalf("going in answered %d to %q", rec.Code, rec.Header().Get("Location"))
	}
	// Without signing out: the same browser is now inside ana's account, as
	// op-1, able to write.
	rec, cookies = w.do(t, http.MethodGet, "/painel", cookies)
	if rec.Code != http.StatusOK || rec.Body.String() != "ana|op-1|writes" {
		t.Fatalf("the panel inside the account says %d %q", rec.Code, rec.Body.String())
	}

	open, err := w.module.Service().OpenNow(context.Background(), people["op-2"])
	if err != nil || len(open) != 1 || open[0].ActorID != "op-1" || open[0].TargetID != "ana" || !bool(open[0].Acting) {
		t.Fatalf("the open impersonations are %v, %v", open, err)
	}

	rec, cookies = w.do(t, http.MethodPost, impersonate.DefaultPrefix+"/leave", cookies)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/usuarios" {
		t.Fatalf("coming back answered %d to %q", rec.Code, rec.Header().Get("Location"))
	}
	rec, _ = w.do(t, http.MethodGet, "/painel", cookies)
	if rec.Body.String() != "op-1||writes" {
		t.Fatalf("back home the panel says %q", rec.Body.String())
	}

	rows, total, err := w.module.Service().History(context.Background(), people["op-1"], impersonate.HistoryQuery{})
	if err != nil || total != 1 || rows[0].Status != impersonate.Closed || rows[0].EndReason != impersonate.EndLeft {
		t.Fatalf("the history is %d, %+v, %v", total, rows, err)
	}

	entries := w.entries(t)
	if len(entries) != 2 {
		t.Fatalf("the log holds %d entries, want going in and coming back", len(entries))
	}
	for i, event := range []string{"impersonation.taken", "impersonation.left"} {
		e := entries[i]
		if e.Causer().ID != "op-1" || e.Subject().ID != "ana" || e.Event == nil || *e.Event != event {
			t.Errorf("entry %d is %v by %q on %q, want %s by op-1 on ana", i, e.Event, e.Causer().ID, e.Subject().ID, event)
		}
	}
}

func TestTheRefusals(t *testing.T) {
	w := install(t)

	// Somebody without the operator's role is refused.
	rec, _ := w.do(t, http.MethodPost, impersonate.DefaultPrefix+"/take/bruno", w.signIn(t, "ana"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a member going into an account answered %d", rec.Code)
	}
	ctx := context.Background()
	svc := w.module.Service()
	if _, _, err := svc.Take(ctx, people["op-1"], "op-2"); !errors.Is(err, impersonate.ErrNotImpersonable) {
		t.Fatalf("an operator went into another operator's account: %v", err)
	}
	if _, _, err := svc.Take(ctx, people["op-1"], "globex"); !errors.Is(err, impersonate.ErrNotFound) {
		t.Fatalf("an operator went into another tenant's account: %v", err)
	}
	if _, _, err := svc.Take(ctx, people["op-1"], "nobody"); !errors.Is(err, impersonate.ErrNotFound) {
		t.Fatalf("an operator went into an account that does not exist: %v", err)
	}
	if _, _, err := svc.Take(ctx, people["op-1"], "op-1"); err == nil {
		t.Fatal("an operator went into their own account")
	}
	// From inside an account, nowhere else.
	inside, _, err := svc.Take(ctx, people["op-1"], "ana")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Take(ctx, inside, "bruno"); !errors.Is(err, security.ErrForbidden) {
		t.Fatalf("an operator inside one account went into another: %v", err)
	}
	// Leaving from outside an impersonation is refused.
	rec, _ = w.do(t, http.MethodPost, impersonate.DefaultPrefix+"/leave", w.signIn(t, "bruno"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("leaving outside an impersonation answered %d", rec.Code)
	}
}

func TestAnImpersonationPastItsDeadlineTakesTheOperatorBack(t *testing.T) {
	w := install(t)
	cookies := w.signIn(t, "op-1")
	_, cookies = w.do(t, http.MethodPost, impersonate.DefaultPrefix+"/take/ana", cookies)

	// The deadline passes: the row says so.
	open, _ := w.module.Service().OpenNow(context.Background(), people["op-2"])
	open[0].ExpiresAt = time.Now().UTC().Add(-time.Minute)
	if _, err := open[0].Save(context.Background(), security.SystemGrant(impersonate.ImpersonateHistory, tenant)); err != nil {
		t.Fatal(err)
	}

	rec, cookies := w.do(t, http.MethodGet, "/painel", cookies)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/usuarios" {
		t.Fatalf("a lapsed impersonation answered %d to %q", rec.Code, rec.Header().Get("Location"))
	}
	rec, _ = w.do(t, http.MethodGet, "/painel", cookies)
	if rec.Body.String() != "op-1||writes" {
		t.Fatalf("after the deadline the panel says %q", rec.Body.String())
	}
	rows, _, _ := w.module.Service().History(context.Background(), people["op-1"], impersonate.HistoryQuery{})
	if rows[0].Status != impersonate.Closed || rows[0].EndReason != impersonate.EndExpired {
		t.Fatalf("the lapsed impersonation reads %+v", rows[0])
	}
	entries := w.entries(t)
	if last := entries[len(entries)-1]; last.Event == nil || *last.Event != "impersonation.expired" || last.Causer().ID != "op-1" {
		t.Fatalf("the last entry is %v by %q", last.Event, last.Causer().ID)
	}
}

func TestTheApplicationKeepsAccountsOutOfReach(t *testing.T) {
	w := install(t)
	if _, _, err := w.module.Service().Take(context.Background(), people["op-1"], "chefe"); !errors.Is(err, impersonate.ErrNotImpersonable) {
		t.Fatalf("an account the application protects was impersonated: %v", err)
	}
}

func TestAProtectedRouteRefusesSomebodyImpersonating(t *testing.T) {
	w := install(t)

	// The owner reaches it.
	rec, _ := w.do(t, http.MethodPost, "/painel/seguranca/senha", w.signIn(t, "ana"))
	if rec.Code != http.StatusOK {
		t.Fatalf("the owner was refused their own security page: %d", rec.Code)
	}

	// The impersonator acting as them does not, and is sent back.
	cookies := w.signIn(t, "op-1")
	_, cookies = w.do(t, http.MethodPost, impersonate.DefaultPrefix+"/take/ana", cookies)
	rec, _ = w.do(t, http.MethodPost, "/painel/seguranca/senha", cookies)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/painel" {
		t.Fatalf("a protected route answered %d to %q while impersonating", rec.Code, rec.Header().Get("Location"))
	}
	if rec.Body.String() == "password changed" {
		t.Fatal("the protected handler ran")
	}
}
