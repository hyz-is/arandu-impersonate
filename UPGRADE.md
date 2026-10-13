# Upgrade Guide

## Unreleased

## v0.1.0

The first release, and the successor of hyz-is/arandu-inspect v0.1.0, which is
archived. Install arandu-activitylog v0.3.0 beside it (hesape v0.58.0 or newer
comes with it), wire it in `bootstrap/app.go` as the README shows, mount
`Guard()` after `RequireAuth` on the routes reachable from inside an account and
`Protect()` on the ones only the owner may reach, run `aru migrate`, draw the
bar from `view.Impersonation` in the layout, and give the platform's managers
the role `impersonate.impersonator` through arandu-permission.
