<p align="center">
  <img src=".github/logo.svg" alt="Arandu" width="180">
</p>

# Arandu Impersonate

An operator goes into a user's account from the admin, **without signing out
of their own**, acts there as the user — sees what the user sees, changes what
the user can change — and comes back with one click. Every visit has a
deadline, and everything is recorded in
[arandu-activitylog](https://github.com/hyz-is/arandu-activitylog) under the
operator's name, with the account it was done in.

It is [laravel-impersonate](https://github.com/404labfr/laravel-impersonate)
for Arandu, and the "inspecionar" of the team's consoles: the platform's
manager -- never a member an account invited -- takes a user's place. Who may
impersonate is a Policy, who may be impersonated is the application's answer,
nobody impersonates from inside an account, and nothing done inside goes
unlogged.

## Parity with laravel-impersonate

| laravel-impersonate | here |
| --- | --- |
| `canImpersonate()` | the policy: the role `impersonate.impersonator`, given through arandu-permission |
| `canBeImpersonated()` | `Config.CanBeImpersonated`; an impersonator's account is never impersonated |
| no impersonating yourself, nor from inside an impersonation | the same refusals |
| routes `impersonate` and `impersonate.leave`, `take_redirect_to`, `leave_redirect_to` | the same names; `TakeRedirectTo`, `LeaveRedirectTo` |
| `ProtectFromImpersonation` middleware | `Protect()` |
| `@impersonating` in Blade | `view.Impersonation` in the layout (hesape v0.58.0) |
| `TakeImpersonation`, `LeaveImpersonation` events | entries in arandu-activitylog, with every act done inside |
| -- | a deadline (`Guard()`), the history, acting or only viewing |

## How it works

- `POST /impersonate/take/{id}` — the operator goes into the account. The session
  is rotated to the account's owner with the operator kept as the one acting
  (hesape `auth.ImpersonateActing`), so the very same browser is now inside the
  account and every Grant writes as the owner would. The visit is recorded as
  an impersonation with a deadline (one hour by default), and as the entry
  `impersonation.taken` in the `impersonate` log.
- Inside the account, every entry the application records names **the
  operator** as its causer and carries the `impersonation` property — `by`,
  `on_behalf_of`, `mode: acting` — which arandu-activitylog v0.3.0 adds by
  itself.
- `POST /impersonate/leave` (route name `impersonate.leave`) — the operator comes back:
  the session is rotated to their own subject, the impersonation is closed and
  `impersonation.left` is recorded.
- `Guard()` — past the deadline, the next request inside the account takes the
  operator back, closes the impersonation and records `impersonation.expired`.
- `GET /impersonate/history` — the impersonations, newest first, for an impersonator.

## Protect what only the owner does

Mount `Protect()` on the routes an impersonator must not reach even acting as
the user -- the password, the e-mail, the two factors, deleting the account,
paying:

```go
	security := r.Group("/painel/seguranca", middleware.RequireAuth(sessions), impersonateModule.Protect())
```

A browser is sent back where it came from; a JSON client is answered 403.

## The bar

Every page built with `view.New` (hesape v0.58.0) knows it is drawn for an
operator inside somebody's account and where the way back is. The
application's layout draws the bar from `view.Impersonation`:

```go
@if(impersonating(.))
	<div class="..." role="status">
		Você está na conta deste usuário como administrador.
		<form method="post" action="{{ leaveLink(.) }}">@csrf<button>Voltar ao administrador</button></form>
	</div>
@endif
```

with, in the layout's `@go` block:

```go
func impersonating(d hview.Layout) bool {
	i, ok := d.(hview.Impersonation)
	return ok && i.IsImpersonating()
}
```

## Install

```bash
go get github.com/hyz-is/arandu-activitylog@v0.3.0
go get github.com/hyz-is/arandu-impersonate
```

It needs hesape v0.58.0 or newer.

## Wire it

In `bootstrap/app.go`, after the session store and the activity log exist:

```go
	impersonateModule, err := impersonate.New(impersonate.Config{
		Targets:  impersonate.TargetsFunc(users.ImpersonationTarget), // the account as its owner signs in
		Activity: activityModule.Logger(),
		TakeRedirectTo:  "/painel",
		LeaveRedirectTo:   "/admin/usuarios",
	}, db, sessions)
	if err != nil {
		return App{}, err
	}
```

register `impersonateModule` in `k.Register(...)`, mount the guard after
`RequireAuth` on the routes reachable from inside an account:

```go
	panel := r.Group("/painel", middleware.RequireAuth(sessions), impersonateModule.Guard())
```

and run `aru migrate`. `Targets` answers the subject the account's owner signs
in as — identifier, tenant, roles, actions — because the package keeps no
users.

## Who may be impersonated

```go
	CanBeImpersonated: func(ctx context.Context, target security.Subject) bool {
		return !target.HasRole("super-admin")
	},
```

## Give people access

`impersonate.impersonator` is the role that takes users' places and reads the history -- in a
multi-tenant application, the platform manager's, never a role an account gives its invited members;
the application gives it through
[arandu-permission](https://github.com/hyz-is/arandu-permission). An account
that carries the role is never impersonated.

## Configuration

| field | required | meaning |
| --- | --- | --- |
| `Targets` | yes | loads the account an operator goes into. |
| `Activity` | yes | arandu-activitylog's logger. |
| `Prefix` | no | where the routes are mounted. Defaults to `/impersonate`. |
| `TakeRedirectTo` | no | where the operator lands inside the account. Defaults to `/`. |
| `LeaveRedirectTo` | no | where they land back in their own. Defaults to `/`. |
| `TTL` | no | how long a visit lasts. Defaults to one hour; at most 12 hours. |
| `UserType` | no | the kind the activity log names accounts by. Defaults to `user`. |

## The data path

`Impersonation` embeds `model.Model` and declares its table beside it.
`aru model:build` generates `ImpersonationQuery.go` with `Impersonations(db)`,
committed and never edited by hand; `aru model:build --check` fails when it is
out of date. `ImpersonateService` follows
`validate -> security.Authorize -> Grant -> Model terminal` in every exported
method, which the unit suite audits, and every route sits behind
`RequireAuth`.

## Example

```bash
go run -tags example ./example
```

It opens SQLite in a temporary directory, migrates arandu-activitylog and this
package, and drives one browser: the operator goes into a user's account,
changes a setting there, comes back, and the activity log is printed with every
entry under the operator's name. It leaves nothing behind. The build tag is
there so that installing this package never compiles it.

## Tests

```bash
GOWORK=off go test ./... -race
```

The feature suite runs the whole visit in one browser against SQLite: going
in, acting as the owner, coming back, the deadline, and every refusal, with
the activity log's entries checked; the rules were checked by mutation.

## Licence

MIT. See [LICENSE.md](LICENSE.md).
