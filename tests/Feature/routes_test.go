package feature_test

import (
	"net/http"
	"sort"
	"testing"
	"time"

	"github.com/arandu-io/framework/data"
	"github.com/arandu-io/framework/http/middleware"
	"github.com/arandu-io/framework/security"
	"github.com/arandu-io/hesape/database/migrations"
	activitylog "github.com/hyz-is/arandu-activitylog"

	impersonate "github.com/hyz-is/arandu-impersonate"
)

func TestAVisitorWithNoSessionIsSentToSignIn(t *testing.T) {
	w := install(t)
	for _, r := range []struct{ method, target string }{
		{http.MethodPost, impersonate.DefaultPrefix + "/take/ana"},
		{http.MethodPost, impersonate.DefaultPrefix + "/leave"},
		{http.MethodGet, impersonate.DefaultPrefix + "/history"},
	} {
		rec, _ := w.do(t, r.method, r.target, nil)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != middleware.SignInPath {
			t.Errorf("%s %s answered %d to %q", r.method, r.target, rec.Code, rec.Header().Get("Location"))
		}
	}
}

func TestTheModuleRegistersItsRoutesByName(t *testing.T) {
	w := install(t)
	var got []string
	for _, route := range w.router.Routes() {
		if route.Module == "impersonate" {
			got = append(got, route.Method+" "+route.Pattern+" "+route.GetName())
		}
	}
	sort.Strings(got)
	want := []string{
		"GET /impersonate/history impersonate.history",
		"POST /impersonate/leave impersonate.leave",
		"POST /impersonate/take/{id} impersonate",
	}
	if len(got) != len(want) {
		t.Fatalf("registered %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("registered %v, want %v", got, want)
		}
	}
}

func TestNewRefusesAWiringThatCannotWork(t *testing.T) {
	sessions := security.NewSessionStore([]byte(appKey), time.Hour, false, security.NewMemoryBackend())
	handle := data.Wrap(nil, data.DialectSQLite)
	activity, err := activitylog.New(activitylog.Config{Tenant: tenant}, handle, sessions)
	if err != nil {
		t.Fatal(err)
	}
	valid := impersonate.Config{Targets: targets, Activity: activity.Logger()}
	for name, cfg := range map[string]impersonate.Config{
		"no targets":           {Activity: activity.Logger()},
		"no activity log":      {Targets: targets},
		"a deadline too long":  {Targets: targets, Activity: activity.Logger(), TTL: impersonate.MaxTTL + time.Minute},
		"a landing elsewhere":  {Targets: targets, Activity: activity.Logger(), TakeRedirectTo: "//evil.example"},
		"a prefix that is bad": {Targets: targets, Activity: activity.Logger(), Prefix: "/x{"},
	} {
		if _, err := impersonate.New(cfg, handle, sessions); err == nil {
			t.Errorf("a configuration with %s was accepted", name)
		}
	}
	if _, err := impersonate.New(valid, nil, sessions); err == nil {
		t.Error("a nil database handle was accepted")
	}
	if _, err := impersonate.New(valid, handle, nil); err == nil {
		t.Error("a nil session store was accepted")
	}
	m, err := impersonate.New(valid, handle, sessions)
	if err != nil {
		t.Fatalf("a valid wiring was refused: %v", err)
	}
	for _, migration := range m.Migrations() {
		if _, ok := migration.(migrations.ReversibleMigration); !ok {
			t.Errorf("the migration %s has no Down", migration.GetName())
		}
	}
}
