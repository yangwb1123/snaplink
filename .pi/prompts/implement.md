<!-- Implement Agent: follow the feature spec -->
Read feature-spec-<name>.md. Follow it strictly.
After each Go edit:

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
```

When done, run targeted tests and `make ci`.
