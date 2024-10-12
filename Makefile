.PHONY: proto
proto:
	protoc -I $(HOME)/dev/threat.gg --go-grpc_out=proto/ --go-grpc_opt=paths=source_relative --go_out=proto/ --go_opt=paths=source_relative ~/dev/threat.gg/honeypot.proto
