# Upgrade Guide

## Unreleased

Go 1.26.10 is the floor: `go.mod` declares `go 1.26.10`, because every
vulnerability an Arandu application reaches is in the standard library and is
fixed there (crypto/x509, net/http HTTP/2 and CONNECT, html/template,
net/textproto, crypto/tls). A build on an older toolchain fetches 1.26.10 or
fails when `GOTOOLCHAIN=local`.

This release selects Framework v0.66.0, Hesape v0.85.0 and arandu-activitylog
v0.6.0; read their upgrade guides from the versions the application required
before (Framework v0.58.0, Hesape v0.69.0 and arandu-activitylog v0.3.0 in
v0.3.1).

The session store must have the application's `SubjectResolver`
(`sessions.ResolveSubjects`). Hesape refuses to start or rotate a session for a
subject carrying roles or actions without one, and going into an account
rotates the session to the account as its owner signs in, roles included:
without a resolver, `POST` to the route `impersonate.take` fails with
`ErrNoSubjectResolver`. With one, the session keeps who is inside whose
account, and the roles and actions of both the account and the operator are
read afresh on every request. The skeleton installs it; an application that
signs people in without one installs one that answers each account as
`Targets` does.

`apidiff` reports `New` and `(*Module).Routes` as changed. Their signatures
read as before; what moved is underneath the names they take: Framework
v0.63.0 declares `security.SessionStore` as an alias of hesape's
`http.SessionStore` and `fhttp.Router` as an alias of hesape's
`controllers.Router`, where v0.58.0 declared structs of its own. An application
on Framework v0.66.0 passes the store and the router it already builds and
changes nothing; one that stays on an older Framework cannot take this release.

`ImpersonatePolicy` implements `auth.Writes`: `ImpersonateTake` and
`ImpersonateLeave` write, and a Grant `security.Authorize` issues for
`ImpersonateHistory` only reads, so the database refuses any insert, update or
delete made with it (`auth.ErrReadGrant`). Nothing in this package writes with
such a Grant; an application that reused one to write its own rows gets the
refusal and authorizes that write for an action that writes.

## v0.3.1

Run `aru migrate`: `20261020_0001_widen_impersonations_time_precision` raises
the five instants of `impersonations` from whole seconds to microseconds where
a release before Hesape v0.67.0 created them so. On PostgreSQL it changes the
type modifier only and rewrites neither the table nor its indexes; on MySQL the
columns are restated with `MODIFY`, which may copy the table. No visit changes.
A process still running the previous binary may see PostgreSQL refuse a cached
plan over the table once per connection ("cached plan must not change result
type"): migrate before the new binary starts.

This release selects Framework v0.58.0 and Hesape v0.69.0; follow their upgrade
notes between the versions you had and these. No symbol of this package
changes.

## v0.3.0

Run the migration (`aru migrate`): it adds the column `reason` to
`impersonations`.

A call to `ImpersonateService.Take` (`(*ImpersonateService).Take`) passes the
reason as its fourth argument, `""` where there is none:

```go
	acting, record, err := impersonations.Take(ctx, operator, userID, "chamado 4512")
```

An application that asks its operators why they go in sets
`Config.RequireReason` and adds a field named `reason` to the form that posts
to the route `impersonate`; the router needs its flash
(`Router.WithFlash`), as every form of the application does, to send a refusal
back with the message on the field.

## v0.2.2

An application whose permissions arandu-permission administers, and that
grants its platform managers `impersonate.take` and `impersonate.history`,
hands the module the middleware that resolves them:

```go
	impersonate.Config{
		// ...
		Middleware: []func(http.Handler) http.Handler{permissionModule.Roles()},
	}
```

Without it the routes see the subject the session stored, which carries no
actions, and refuse the manager. An application that fills `Roles` with
`impersonate.impersonator` itself, or stores the actions in the session,
changes nothing.

## v0.2.1

An application that granted the action `impersonate` (only possible outside `arandu-permission`) grants `impersonate.take` instead; take the value from `ImpersonateTake` or `Actions()` rather than writing it. Applications that fill the role `impersonate.impersonator` change nothing.

## v0.2.0

### Platform managers can hold the actions instead of the role

An application whose permissions arandu-permission administers grants the
actions:

```go
	permission.Config{
		Actions: append(append(myapp.Actions(), permission.Actions()...), impersonate.Actions()...),
	}
```

and puts `impersonate` and `impersonate.history` in the platform managers'
group. Nothing else changes: an application that fills `Roles` with
`impersonate.impersonator` keeps working as it did. One that put the role into
the session by hand after its own platform policy allowed it -- the way around
this defect -- can drop that step.

An account holding the action `impersonate` is now refused as a target with
`ErrNotImpersonable`, as one carrying the role was. An application that let a
manager holding only the action be impersonated sees that refusal now.

### The package skill

`Config.Targets` and `Config.Activity` are required, as they were in v0.1.0:
the `impersonate-package` skill said otherwise, and `aru skills:sync` brings
the corrected one. Nothing changes in code that already passed both.

## v0.1.0

The first release, and the successor of hyz-is/arandu-inspect v0.1.0, which is
archived. Install arandu-activitylog v0.3.0 beside it (hesape v0.58.0 or newer
comes with it), wire it in `bootstrap/app.go` as the README shows, mount
`Guard()` after `RequireAuth` on the routes reachable from inside an account and
`Protect()` on the ones only the owner may reach, run `aru migrate`, draw the
bar from `view.Impersonation` in the layout, and give the platform's managers
the role `impersonate.impersonator` through arandu-permission.
