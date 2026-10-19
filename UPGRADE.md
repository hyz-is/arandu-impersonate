# Upgrade Guide

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
