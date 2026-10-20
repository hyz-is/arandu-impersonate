# Changelog

Everything worth knowing about a release of Arandu Impersonate is recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

A published module version is immutable: Go serves it from the proxy forever, so
a release is corrected by another release and never by moving a tag.

## [Unreleased]

## [0.3.1] - 2026-10-20

### Added

- The migration `20261020_0001_widen_impersonations_time_precision`: the
  visits' `started_at`, `expires_at`, `closed_at`, `created_at` and
  `updated_at`, which an earlier framework default created in whole seconds --
  PostgreSQL rounds a value to the second there, MySQL truncates it -- are
  raised to microseconds through Hesape's `migrations.WidenTimePrecision`, so a
  visit reads back the instants it was written with and visits started within
  one second are ordered by the instant and not by the identifier alone. A
  column already in microseconds is left alone, SQLite has nothing to widen,
  and the rollback keeps the columns wide.

### Changed

- Requires Framework v0.58.0 and Hesape v0.69.0, where a date-time column is
  declared in microseconds by default and `migrations.WidenTimePrecision`
  exists. The manifest's framework floor is `>= 0.58`. The suite requires the
  PostgreSQL connector v0.11.0, and CI runs it against a PostgreSQL service.

## [0.3.0] - 2026-10-19

### Added

- A reason for going into an account. The take route reads the form field
  `reason`; it is kept on the impersonation (`Impersonation.Reason`, the
  history's `reason`) and as the property `reason` of the entry of going in.
  At most `MaxReasonLen` (500) characters.
- `Config.RequireReason`: refuses going in without a reason, as
  `validation.Errors` on the field `reason`.
- Migration `20261019_0001_add_reason_to_impersonations`: the column `reason`
  on `impersonations`, empty for the visits made before it.

### Changed

- `ImpersonateService.Take` takes the reason as its fourth argument. Pass `""`
  where there is none.

## [0.2.2] - 2026-10-19

### Added

- `Config.Middleware`: middleware the module's routes run after `RequireAuth`.
  An application whose permissions arandu-permission administers mounts its
  `Roles()` there.

### Fixed

- A platform manager granted `impersonate.take` through arandu-permission was
  refused going in and reading the history: the routes run `RequireAuth`,
  which puts the subject as the session stored it, without the actions
  arandu-permission resolves on each request. With `Roles()` in
  `Config.Middleware` the policy sees them.

## [0.2.1] - 2026-10-18

### Fixed

- `ImpersonateTake` is now `impersonate.take`. v0.2.0 named it `impersonate`, which `hyz-is/arandu-permission` refuses in a catalogue because it is not in `module.verb` form, so the action could not be granted through it as the README said.

## [0.2.0] - 2026-10-18

### Added

- `Actions()`, the two actions an application grants (`impersonate` and
  `impersonate.history`), to splice into arandu-permission's
  `Config.Actions`, and `IsOperator(s)`, whether a subject carries
  `ImpersonatorRole` or holds `ImpersonateTake`.

### Fixed

- The policy opens `ImpersonateTake` and `ImpersonateHistory` to a subject that
  holds the action, besides one carrying `ImpersonatorRole`. arandu-permission
  fills the Subject's `Actions` and never its `Roles`, so a platform manager
  whose access it administers was refused both. Each action opens only itself.

### Changed

- An account holding the action `impersonate` is an operator's and is never
  impersonated, as an account carrying `ImpersonatorRole` already was.

### Documentation

- The `impersonate-package` skill said no `Config` field was required and wired
  `impersonate.Config{}`, which `New` refuses: `Targets` and `Activity` are
  required. It now wires both, lists every field, the three routes this
  package registers and the rules its policy ships, in place of the template
  routes, `PageSize` and the "refuses everybody" policy it still described. The
  README lists `CanBeImpersonated`.

## [0.1.0] - 2026-10-13

The first release: laravel-impersonate for Arandu, with every act logged.

### Added

- `POST /impersonate/take/{id}` (`impersonate`): the session is rotated to the
  user with the impersonator acting (hesape `auth.ImpersonateActing`); the visit
  is an `Impersonation` with a deadline and the entry `impersonation.taken` in
  the `impersonate` activity log.
- `POST /impersonate/leave` (`impersonate.leave`, the route hesape v0.58.0's
  `view.New` links the way back by): back to the impersonator's own session,
  `impersonation.left` recorded.
- `Guard()`: past the deadline the impersonator is taken back and
  `impersonation.expired` recorded.
- `Protect()`: laravel-impersonate's `ProtectFromImpersonation`.
- `Config.CanBeImpersonated`: laravel-impersonate's `canBeImpersonated`.
- `GET /impersonate/history` and `ImpersonateService.OpenNow`.
- The role `impersonate.impersonator`, whose accounts are never impersonated.
- The actions `ImpersonateTake`, `ImpersonateLeave` and `ImpersonateHistory`.
- The migration `20261013_0001_create_impersonations`.

