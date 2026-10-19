---
name: impersonate-package
description: Install, wire and use the Arandu Impersonate package (Go, Arandu) in an application. Use when the request is to "install Arandu Impersonate", "add impersonate to the app", "go get github.com/hyz-is/arandu-impersonate", "wire it into bootstrap/app.go", "register the module", "use the impersonate routes", "everything under /impersonate returns 403", "403 forbidden from impersonate", "it redirects to /auth/login", "the table does not exist", "no such table", "change where it is mounted", "let admins read it", "impersonate.New refuses a nil Targets", "Config.Activity is nil", "a platform manager gets 403", or when a project's go.mod already requires github.com/hyz-is/arandu-impersonate. Covers the wiring and where each line goes, the Config fields and the two that are required (Targets and Activity), the routes, their names and the session they need, who the policy lets in (the impersonate actions or the impersonator role), and the migration step that is not optional.
license: MIT
metadata:
  audience: app
---

# Using Arandu Impersonate

An Arandu package with one entity, its own table, its own routes and its own
policy. It is registered by hand — there is no service provider, no container
and no discovery, so if a line is not written in the application, it does not
happen.

## Install

```bash
go get github.com/hyz-is/arandu-activitylog
go get github.com/hyz-is/arandu-impersonate
```

arandu-activitylog is not optional: everything an operator does inside an
account is recorded there under the operator's name, and `New` refuses to
build without its logger.

## The wiring, and where it goes

All of it is in `bootstrap/app.go`. Nothing else in the application changes,
and `aru make:module` does not edit this file for you.

The import, with the other module imports:

```go
import (
	impersonate "github.com/hyz-is/arandu-impersonate"
)
```

The construction, in `Build`, after the session store and the activity log
module exist and before `k.Register`:

```go
	impersonateModule, err := impersonate.New(impersonate.Config{
		Targets:  impersonate.TargetsFunc(users.ImpersonationTarget), // required
		Activity: activityModule.Logger(),                             // required
	}, db, sessions)
	if err != nil {
		return App{}, err
	}
```

The registration, inside the `k.Register(...)` call already there:

```go
		impersonateModule,
```

and the guard, after `RequireAuth`, on the routes an operator reaches from
inside an account:

```go
	panel := r.Group("/painel", middleware.RequireAuth(sessions), impersonateModule.Guard())
```

`New` returns an error rather than starting half-wired. It refuses a nil
`Config.Targets`, a nil `Config.Activity`, a setting that cannot work, a nil
database handle and a nil session store, so a wiring mistake costs one restart
instead of arriving as a nil dereference on the first request that needed it.
`impersonate.Config{}` is **not** a complete configuration.

## Then run the migrations

```bash
aru migrate
```

Not optional, and not automatic. The package owns a table, which is why its
`arandu.mod.toml` declares `migrations = true` — that declaration is how an
installer finds out before deploying rather than from the first request.
arandu-activitylog's migrations run in the same step.

`aru migrate` is a step in the pipeline and never a call at the start of the
process: with N replicas, N migrations race each other.

**Symptom to recognise:** `no such table`, or `relation does not exist`, from a
route that authorized correctly. The migration has not run.

## Configuration

| field | required | meaning |
| --- | --- | --- |
| `Targets` | **yes** | loads the account an operator goes into: the subject its owner signs in as. The package keeps no users. `New` refuses nil |
| `Activity` | **yes** | arandu-activitylog's logger, `activityModule.Logger()`. `New` refuses nil |
| `Prefix` | no | where the routes are mounted. Defaults to `/impersonate` |
| `TakeRedirectTo` | no | where the operator lands inside the account. Defaults to `/` |
| `LeaveRedirectTo` | no | where they land back in their own. Defaults to `/` |
| `TTL` | no | how long a visit lasts. Defaults to one hour, refused above 12 hours |
| `UserType` | no | the kind the activity log names accounts by. Defaults to `user` |
| `CanBeImpersonated` | no | the application's answer to whether an account may be gone into at all. Nil lets every account through except an operator's |
| `Middleware` | no | runs on the module's routes after `RequireAuth`; an application whose permissions arandu-permission administers passes `permissionModule.Roles()`, or the policy sees no actions and refuses its platform managers |

There is no tenant to pass: every route needs a session, and the tenant of
every statement comes from `data.Tenant(g)`, off the Grant of whoever is signed
in. Passing a value the request named — a path segment, a header, a subdomain
read off the URL — is what `TestNoTenantIsReadOutOfTheRequest` fails on in the
package. In an application the same mistake is `aru doctor`'s
`tenant-from-request`; in a package nothing but the package's own suite looks.

A `TTL` above 12 hours is an error from `New`, not a silent 12 hours. A number
somebody wrote and did not get is worse than a number somebody wrote and was
told about.

## Routes

| method | path | name |
| --- | --- | --- |
| `POST` | `/impersonate/take/{id}` | `impersonate` |
| `POST` | `/impersonate/leave` | `impersonate.leave` |
| `GET` | `/impersonate/history` | `impersonate.history` |

Every route sits behind `RequireAuth`, mounted by the package itself. A request
with no session is sent to `/auth/login` — 303, or `HX-Redirect` for an htmx
request — and comes back to the address it asked for after signing in. That is
the sign-in screen the starter kit publishes; an application without one sees
a 404 there.

**Symptom to recognise:** every route of the package redirects to
`/auth/login`. Nobody is signed in on that request: the session cookie did not
arrive, or the session store passed to `New` is not the one the application
signs people in with.

Build URLs from the names, never by writing the path a second time. `aru
route:list` shows them grouped by module. Under a custom `Prefix` the paths move
and the names do not. `impersonate.leave` is also the name hesape's `view.New`
links the way back by.

`GET /impersonate/history` answers `{"items": [...], "total": n}` inside the
framework's `data` envelope, newest first, 50 to a page (`?page=`), filtered
by `?actor=`, `?target=` and `?status=`.

`TenantID` is not in any response. That is deliberate: it names a customer's
identifier and the response is a declared list of fields rather than the entity.

## Who may go in

`ImpersonatePolicy` denies unless a rule allows, and it ships these rules:

- `impersonate` and `impersonate.history`: a subject that holds the action, or
  carries the role `impersonate.impersonator`. An application whose
  permissions arandu-permission administers splices `impersonate.Actions()`
  into `permission.Config.Actions` and puts both in the platform managers'
  group; arandu-permission fills `Actions`, never `Roles`. One that decides by
  role gives the role.
- `impersonate.leave`: the operator the impersonation names.
- Nobody, from inside an account, and no guest.

An account that holds the role or the action `impersonate.take` is an operator's and
is never impersonated; `Config.CanBeImpersonated` keeps any other account out
of reach.

**Symptom to recognise:** a platform manager gets 403 from
`POST /impersonate/take/{id}`. The subject holds neither the action nor the
role — with arandu-permission, the action is missing from the group or from
`permission.Config.Actions`.

**Do not open it from the application.** There is no hook, no override and no
config flag for the policy, and adding one would be a second place where
authorization is decided. If the rules this application needs are not the rules
the package ships, the change belongs in the package.

## What the answers mean

| status | what happened |
| --- | --- |
| `303` to `/auth/login` | there is no session on the request |
| `403` | the policy refused, or no rule allows the action yet |
| `404` | no row with that id in this tenant |
| `303` back to the page the request came from | the input was rejected; the messages and what was typed are in the flash |
| `422` `application/problem+json` | the input was rejected and the request asked for JSON; the messages are in `errors`, keyed by field |

A request that asks for JSON (an `Accept` naming `application/json`, or an XHR
that is not htmx) gets the 403 and the 404 as problem documents too. The
sign-in redirect is the same for every client.

The package does not choose these: its handlers return what the service
returned, and the framework's router answers it. A refusal carries no detail
beyond the status and its standard sentence. Telling a client why a policy said
no tells it what exists and what does not, one request at a time. The reason is
in the log.

Anything else is a 500 and the framework's error page in development. The
package returns unexpected errors rather than swallowing them, so a route that
answers 200 with an empty body is not something it does.

## Reporting a problem

Issues and pull requests go to the repository the module path names,
`github.com/hyz-is/arandu-impersonate`, which belongs to `hyz-is`. A vulnerability goes to the
private advisory form named in that repository's `SECURITY.md`, and never into
an issue.

MIT licensed. Copyright Paulo R. Lima.
