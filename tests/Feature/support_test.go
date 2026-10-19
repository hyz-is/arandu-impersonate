package feature_test

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arandu-io/framework/data"
	fhttp "github.com/arandu-io/framework/http"
	"github.com/arandu-io/framework/http/middleware"
	"github.com/arandu-io/framework/security"
	"github.com/arandu-io/hesape/auth"
	hedatabase "github.com/arandu-io/hesape/database"
	sqliteconnector "github.com/arandu-io/hesape/database/connectors/sqlite"
	activitylog "github.com/hyz-is/arandu-activitylog"

	impersonate "github.com/hyz-is/arandu-impersonate"
)

const (
	appKey = "0123456789abcdef0123456789abcdef"
	tenant = "acme"
	dsn    = "?_txlock=immediate&_pragma=journal_mode(WAL)&_pragma=busy_timeout(20000)"
)

// people are the accounts the application knows, by identifier.
var people = map[string]security.Subject{
	"op-1":   {ID: "op-1", Tenant: tenant, Roles: []string{impersonate.ImpersonatorRole}, Verified: true},
	"op-2":   {ID: "op-2", Tenant: tenant, Roles: []string{impersonate.ImpersonatorRole}, Verified: true},
	"ana":    {ID: "ana", Tenant: tenant, Roles: []string{"member"}, Verified: true},
	"bruno":  {ID: "bruno", Tenant: tenant, Verified: true},
	"globex": {ID: "globex", Tenant: "globex", Verified: true},
	"chefe":  {ID: "chefe", Tenant: tenant, Roles: []string{"super-admin"}, Verified: true},
	// A platform manager whose permissions arandu-permission administers: the
	// actions, and no role.
	"gestora": {ID: "gestora", Tenant: tenant, Verified: true, Actions: []security.Action{impersonate.ImpersonateTake, impersonate.ImpersonateHistory}},
	// The same manager as an application that resolves actions on each
	// request keeps her in the session: no actions at all.
	"resolvida": {ID: "resolvida", Tenant: tenant, Verified: true},
}

// resolved is what arandu-permission's Roles() does for "resolvida": the
// actions read from the permission store on each request, onto the subject
// RequireAuth put on the request.
func resolved(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subject, ok := auth.SubjectFrom(r.Context()); ok && subject.ID == "resolvida" && subject.Impersonator == nil {
			subject.Actions = []security.Action{impersonate.ImpersonateTake, impersonate.ImpersonateHistory}
			r = r.WithContext(auth.WithSubject(r.Context(), subject))
		}
		next.ServeHTTP(w, r)
	})
}

// targets answers the application's accounts.
var targets = impersonate.TargetsFunc(func(_ context.Context, _ string, id string) (security.Subject, error) {
	return people[id], nil
})

// world is an application with arandu-activitylog and arandu-impersonate over a
// real database, a session store, and a panel route of its own.
type world struct {
	db       *data.DB
	module   *impersonate.Module
	sessions *security.SessionStore
	router   *fhttp.Router
	now      *time.Time
}

func install(t *testing.T, resolvers ...func(http.Handler) http.Handler) *world {
	t.Helper()
	path := filepath.Join(t.TempDir(), "impersonate.sqlite")
	handle, err := sql.Open(sqliteconnector.SQLiteConnector{}.DriverName(), "file:"+path+dsn)
	if err != nil {
		t.Fatal(err)
	}
	handle.SetMaxOpenConns(4)
	t.Cleanup(func() { _ = handle.Close() })
	connection := hedatabase.NewConnection(handle, path, "", map[string]any{"driver": string(hedatabase.DialectSQLite), "name": "impersonate-test"})
	db := data.Wrap(handle, data.DialectSQLite)
	sessions := security.NewSessionStore([]byte(appKey), time.Hour, false, security.NewMemoryBackend())

	activity, err := activitylog.New(activitylog.Config{Tenant: tenant}, db, sessions)
	if err != nil {
		t.Fatal(err)
	}
	module, err := impersonate.New(impersonate.Config{
		Targets: targets, Activity: activity.Logger(),
		// The application keeps its super admins out of reach, as
		// laravel-impersonate's canBeImpersonated would.
		CanBeImpersonated: func(_ context.Context, target security.Subject) bool { return !target.HasRole("super-admin") }, TakeRedirectTo: "/painel", LeaveRedirectTo: "/admin/usuarios", TTL: 30 * time.Minute,
		Middleware: resolvers,
	}, db, sessions)
	if err != nil {
		t.Fatal(err)
	}
	migrations := hedatabase.ForMigrations(connection)
	for _, m := range append(activity.Migrations(), module.Migrations()...) {
		if err := m.Up(context.Background(), migrations); err != nil {
			t.Fatalf("applying %s: %v", m.GetName(), err)
		}
	}

	router := fhttp.NewRouter()
	module.Routes(router.ForModule(module.Name()))
	// The application's panel: who the session says is here, and whether
	// they could write.
	panel := router.Group("", middleware.RequireAuth(sessions), module.Guard())
	panel.Action(http.MethodGet, "/painel", func(ctx *fhttp.Context) error {
		who, _ := ctx.User()
		g, err := security.Authorize(ctx.Ctx(), allowAll{}, who, "panel.view", struct{}{})
		if err != nil {
			return err
		}
		by := ""
		if who.Impersonator != nil {
			by = who.Impersonator.ID
		}
		writes := "writes"
		if g.ReadOnly() {
			writes = "reads"
		}
		_, err = ctx.Response.Write([]byte(who.ID + "|" + by + "|" + writes))
		return err
	})
	// What only the owner does, even with an impersonator acting as them.
	protected := router.Group("", middleware.RequireAuth(sessions), module.Protect())
	protected.Action(http.MethodPost, "/painel/seguranca/senha", func(ctx *fhttp.Context) error {
		_, err := ctx.Response.Write([]byte("password changed"))
		return err
	})
	now := time.Now().UTC()
	w := &world{db: db, module: module, sessions: sessions, router: router, now: &now}
	return w
}

type allowAll struct{}

func (allowAll) Can(context.Context, security.Subject, security.Action, struct{}) error { return nil }

// signIn starts a session for an account and answers its cookies.
func (w *world) signIn(t *testing.T, id string) []*http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	if _, err := w.sessions.Start(context.Background(), rec, people[id]); err != nil {
		t.Fatal(err)
	}
	return rec.Result().Cookies()
}

// do sends a request with the cookies, and answers the response and the
// cookies the browser holds after it.
func (w *world) do(t *testing.T, method, target string, cookies []*http.Cookie) (*httptest.ResponseRecorder, []*http.Cookie) {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.router.ServeHTTP(rec, req)
	held := map[string]*http.Cookie{}
	for _, c := range cookies {
		held[c.Name] = c
	}
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(held, c.Name)
		} else {
			held[c.Name] = c
		}
	}
	out := make([]*http.Cookie, 0, len(held))
	for _, c := range held {
		out = append(out, c)
	}
	return rec, out
}

// entries are the activity log's entries of the tenant, oldest first.
func (w *world) entries(t *testing.T) []*activitylog.Activity {
	t.Helper()
	rows, err := activitylog.Activities(w.db).OrderBy("created_at").OrderBy("id").Get(context.Background(), security.SystemGrant(activitylog.ActivityRecord, tenant))
	if err != nil {
		t.Fatal(err)
	}
	return rows
}
