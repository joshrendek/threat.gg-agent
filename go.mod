module github.com/joshrendek/threat.gg-agent

go 1.21

toolchain go1.21.3

replace github.com/jeroenrinzema/psql-wire => github.com/joshrendek/psql-wire v0.0.0-20240627013058-db7be29b356b

require (
	github.com/cretz/bine v0.0.0-20181016150912-25e2ee8b213c
	github.com/gorilla/mux v1.8.1
	github.com/jellydator/ttlcache/v3 v3.2.0
	github.com/jeroenrinzema/psql-wire v0.11.1
	github.com/joshrendek/hnypots-agent v0.0.0-20200109003340-57ef63b6588e
	github.com/lib/pq v1.10.9
	github.com/quipo/statsd v0.0.0-20171211171823-977fadbd5cda
	github.com/rs/zerolog v1.15.0
	github.com/satori/go.uuid v1.2.0
	golang.org/x/crypto v0.20.0
	golang.org/x/sys v0.17.0
	google.golang.org/grpc v1.43.0
	google.golang.org/protobuf v1.30.0
)

require (
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a // indirect
	github.com/jackc/pgx/v5 v5.0.3 // indirect
	github.com/rogpeppe/go-internal v1.12.0 // indirect
	golang.org/x/net v0.21.0 // indirect
	golang.org/x/sync v0.3.0 // indirect
	golang.org/x/term v0.17.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/genproto v0.0.0-20200526211855-cb27e3aa2013 // indirect
)
