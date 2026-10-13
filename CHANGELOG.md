# Changelog

Everything worth knowing about a release of Arandu Impersonate is recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

A published module version is immutable: Go serves it from the proxy forever, so
a release is corrected by another release and never by moving a tag.

## [Unreleased]

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

