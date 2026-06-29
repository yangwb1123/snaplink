module github.com/snaplink/sso/cmd/sso-mcp

go 1.26.1

replace github.com/snaplink/sso => ../../

require (
	github.com/snaplink/sso v0.0.0-00010101000000-000000000000
	google.golang.org/grpc v1.81.1
)

require (
	golang.org/x/crypto v0.51.0 // indirect
	golang.org/x/net v0.53.0 // indirect
	golang.org/x/sys v0.44.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260401024825-9d38bb4040a9 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)
