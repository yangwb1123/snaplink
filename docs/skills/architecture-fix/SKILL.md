# Skill: Fix an architecture violation

**Trigger:** An import cycle, upward layer import, unclassified package, or
OAuth/OIDC boundary failure.

The legacy `run.py` calls a removed `.check-architecture.sh`; use the committed
tests and `python cli.py architecture` directly.

## Fix patterns

| Violation | Fix |
|---|---|
| `protocols/oauth` imports `protocols/oidc` (or reverse) | Move shared wire type/interface to `shared/core`, or coordinate in `interfaces/sso` |
| domain/protocol imports `interfaces` | Define a small dependency interface in the lower owning package and inject it |
| lower layer imports concrete infrastructure | Define the SPI lower and wire its implementation in composition |
| library imports `cmd` | Move reusable behavior out of the command |
| package is unclassified | Place it under the correct physical layer; classify a genuinely new top-level/`internal` path in `layerName()` |
| existing exemption becomes stale | Remove it; never replace it with another edge |

## Verify

```bash
go test -run 'TestArchitecture_' .
python cli.py architecture
go build ./... && go vet ./...
```
