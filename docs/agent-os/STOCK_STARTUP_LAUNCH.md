# Finite stock launch/configuration binding

## Goal, owner and scope

Migration reviewers must not mistake file-only inspection for the configuration
that stock startup will use. `config.Load(path)` loads only a file. Stock
`main.go` uses `parseRuntimeFlags`, `buildConfigSources` and `LoadFromSources`:
**file < environment < optional etcd < config-bound flags**. SIGHUP reuses that
source chain. Runtime-only flags independently control transports and validation.
An enabled environment reaper can therefore differ from an omitted file interval.
This is a possible divergence, not evidence that a prior/deployed run had it.

This bounded infrastructure/evidence slice extends `migration_guard` and tests
the existing stock composition owner. It adds no endpoint, option, YAML/env key,
SPI, storage migration, dependency, stock behavior or launch command. The guard
is not integrated into stock or CLI and executes nothing. Universal build/vet,
committed Go gates and full CI remain required; independent review remains open.

## Pure version1 launch contract

`startup_launch.validate_launch` accepts a plain exact dictionary with only:

- `version`: actual integer1, not Boolean/coercible numeric;
- `profile`: exact `off` or `on`;
- `config_path`: canonical absolute ASCII POSIX path, at most1024 characters,
  no control characters, ending in `/<profile>-config.json`;
- `argv`: plain list exactly `['-config', config_path, '-grpc-listen', '']`;
- `environment`: complete plain dictionary exactly
  `{'GOMAXPROCS': '4', 'TMPDIR': dirname(config_path) + '/tmp'}`.

The binary is deliberately not supplied in argv; exact binary provenance,
ownership and actual use are separate requirements. There is no shell command.
Only this finite owned-rehearsal context is supported, not general deployment.
All other flags, aliases, implicit gRPC defaults, path mismatches and environment
entries reject, even empty ones. In particular no `SSO_*`, PostgreSQL environment,
etcd/restore/password-file overlay, loader-injection or proxy entry is accepted.
Unknown input is never filtered, repaired, normalized or silently dropped to pass.
A deployed/environment-enabled cleanup setting requires policy/review, not removing
it to manufacture this context. The caller must prove the complete explicit child
environment, not present a filtered excerpt of an inherited one.

Validation is fields → version → profile → path → argv → environment. Count/length
checks bound traversal before hashing. Errors contain only fixed codes:

```text
startup_launch_fields_invalid
startup_launch_version_invalid
startup_launch_profile_invalid
startup_launch_config_path_invalid
startup_launch_argv_invalid
startup_launch_environment_invalid
```

Success returns a SHA256 over ASCII JSON of the complete supplied dictionary
(`sort_keys=True`, `separators=(',', ':')`, `ensure_ascii=True`) and profile, not
paths/environment values. It explicitly returns false for effective-config
verification, complete startup inventory, stock authorization and runtime
certification. It does not open a file/store, run a process, modify its input,
prove provenance/freshness or grant execution authority.

## Effective configuration and source evidence

A caller must separately retain exact source-owner and executable bytes, validate
bounded strict configuration (unknown fields cannot use the stock loader's
warn-and-fallback behavior as admission), and load the **same active chain** using
the exact argv and complete environment. Bind the raw private config SHA and all
resolved root namespaces, including omitted/defaulted families, without printing
credentials or serialized resolved config. Do not call `ServerOptions`, `buildApp`
or constructors merely to inspect configuration. Options are themselves part of
the still-required effect review. Before/after bytes and fingerprints detect only
observed drift; they do not supply same-UID isolation, fencing or future-use proof.

`TestStartupLaunch_ConfigSourceChain` calls the actual stock flag parser/source
builder with synthetic private files: absent-overlay file parity, environment
reaper activation, environment-over-file and CLI-over-environment precedence. It
never builds an app or opens a store/listener. Python boundary cases cover every
required field, noncoercion, path/argv/environment rejection, negative admission
claims, validation order, stable digest binding and nonmutation. Such tests do not
prove durable side-effect safety or historical runtime admission.

## Still blocked before historical stock startup

Combine the launch/configuration evidence with the independently observed
[finite native facts](STOCK_STARTUP_PRESERVATION.md), without promoting either
checker to authorization. Close every reachable migration/load/prune, builtin and
configured seed, option, worker, ordinary persistence path, file/transport and
shutdown effect against exact effective values. Configured namespaces and source
pins alone are not a complete call graph or retention/security policy.

Builtin bootstrap, unconditional revocation Load/Prune and immediate client-secret
scan audit remain independent effects. Preserve separate owned off/on bootstrap
trackers across their own restarts; never prefill them. Never change old expiry,
grants, history, cleanup intervals or bootstrap settings to obtain preservation.
Follow [historical stock-runtime acceptance](HISTORICAL_STOCK_RUNTIME.md) only after
complete prior admission and required review. Preserve Step42's failed full
admission and Step43's unexecuted full inventory/runtime. No retrospective PASS,
closed-fixture replay, production contact/cutover, SVERP topology/session-policy
change, commit, merge or deployment follows from this slice.
