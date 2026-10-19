package impersonate

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/arandu-io/framework/security"
	activitylog "github.com/hyz-is/arandu-activitylog"
)

const (
	// DefaultPrefix is where the routes are mounted when Config leaves Prefix
	// empty.
	DefaultPrefix = "/impersonate"
	// DefaultTTL is how long an impersonation lasts before it lapses.
	DefaultTTL = time.Hour
	// MaxTTL is the longest an impersonation may be configured to last.
	MaxTTL = 12 * time.Hour
	// MaxReasonLen is the longest reason, in characters, an impersonation
	// keeps.
	MaxReasonLen = 500
	// ReasonRequiredMessage is what a refused reason says on its field.
	ReasonRequiredMessage = "Informe o motivo da entrada na conta (até 500 caracteres)."
	// DefaultUserType is the kind the activity log names an account by.
	DefaultUserType = "user"
	// LogName is the activity log the package's own entries go in.
	LogName = "impersonate"
)

// Targets is the application's answer to "who is this account": the subject
// its owner signs in as -- identifier, tenant, roles, actions -- so the
// operator inside the account is exactly what the owner is. The package keeps
// no users of its own.
type Targets interface {
	Target(ctx context.Context, tenant, userID string) (security.Subject, error)
}

// TargetsFunc is a function that answers Targets.
type TargetsFunc func(ctx context.Context, tenant, userID string) (security.Subject, error)

// Target calls f.
func (f TargetsFunc) Target(ctx context.Context, tenant, userID string) (security.Subject, error) {
	return f(ctx, tenant, userID)
}

// Config is everything the module needs from the application.
type Config struct {
	// Prefix is the path the routes are mounted under. Empty means
	// DefaultPrefix.
	Prefix string

	// Targets loads the account an operator goes into. Required.
	Targets Targets

	// Activity is arandu-activitylog's logger. Required: going in, coming
	// back and the deadline passing are entries, and everything done inside
	// the account is recorded under the operator's name by the log itself.
	Activity *activitylog.Logger

	// TakeRedirectTo is where the impersonator lands inside the account, and
	// LeaveRedirectTo where they land back in their own -- laravel-impersonate's
	// take_redirect_to and leave_redirect_to. Empty means "/".
	TakeRedirectTo  string
	LeaveRedirectTo string

	// TTL is how long an impersonation lasts. Zero means DefaultTTL; above
	// MaxTTL is refused.
	TTL time.Duration

	// UserType is the kind the activity log names accounts by, the one the
	// application's own entries use. Empty means DefaultUserType.
	UserType string

	// Middleware runs on the module's routes after RequireAuth, in order. An
	// application whose permissions arandu-permission administers mounts its
	// Roles() here: RequireAuth puts the subject as the session stored it --
	// without the actions arandu-permission resolves on each request -- and
	// without the actions the policy refuses a platform manager who holds
	// impersonate.take. Nil runs nothing more.
	Middleware []func(http.Handler) http.Handler

	// RequireReason refuses going into an account without a reason: the take
	// route reads it from the form field "reason", Take refuses an empty one
	// as validation.Errors on that field, and the reason is kept on the impersonation and on
	// its activity entry. False takes a reason when one is given and goes in
	// without one otherwise.
	RequireReason bool

	// CanBeImpersonated is the application's answer to whether an account may
	// be impersonated at all -- laravel-impersonate's canBeImpersonated: a
	// super admin's account, an account under legal hold. Nil lets every
	// account through, except an operator's -- one IsOperator answers true for
	// -- which is never impersonated whatever this answers.
	CanBeImpersonated func(ctx context.Context, target security.Subject) bool
}

// Validate reports the first setting that cannot work.
func (c Config) Validate() error {
	for _, p := range []struct{ name, value string }{{"Prefix", c.Prefix}, {"TakeRedirectTo", c.TakeRedirectTo}, {"LeaveRedirectTo", c.LeaveRedirectTo}} {
		if p.value != "" && (p.value[0] != '/' || strings.HasPrefix(p.value, "//")) {
			return fmt.Errorf("impersonate: Config.%s is %q and has to be a path of this site, starting with a single /", p.name, p.value)
		}
	}
	if c.Prefix != "" {
		if err := validateRoutePrefix(c.Prefix); err != nil {
			return err
		}
	}
	if c.Targets == nil {
		return fmt.Errorf("impersonate: Config.Targets is nil: the package keeps no users, and has to ask the application who an account is")
	}
	if c.Activity == nil {
		return fmt.Errorf("impersonate: Config.Activity is nil: arandu-impersonate needs arandu-activitylog installed and registered in bootstrap/app.go; pass activityModule.Logger() here")
	}
	for i, mw := range c.Middleware {
		if mw == nil {
			return fmt.Errorf("impersonate: Config.Middleware[%d] is nil", i)
		}
	}
	if c.TTL < 0 || c.TTL > MaxTTL {
		return fmt.Errorf("impersonate: Config.TTL is %s, and has to be between 0 and %s, where 0 means %s", c.TTL, MaxTTL, DefaultTTL)
	}
	return nil
}

// validateRoutePrefix registers the routes' shapes on a scratch mux, which
// panics on a pattern the router would refuse too.
func validateRoutePrefix(prefix string) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("impersonate: Config.Prefix %q cannot be registered as a route path", prefix)
		}
	}()
	mux := http.NewServeMux()
	mux.Handle(http.MethodPost+" "+prefix+"/take/{id}", http.NotFoundHandler())
	mux.Handle(http.MethodPost+" "+prefix+"/leave", http.NotFoundHandler())
	return nil
}

// withDefaults fills what was left empty.
func (c Config) withDefaults() Config {
	if c.Prefix == "" {
		c.Prefix = DefaultPrefix
	}
	if c.TakeRedirectTo == "" {
		c.TakeRedirectTo = "/"
	}
	if c.LeaveRedirectTo == "" {
		c.LeaveRedirectTo = "/"
	}
	if c.TTL == 0 {
		c.TTL = DefaultTTL
	}
	if c.UserType == "" {
		c.UserType = DefaultUserType
	}
	return c
}
