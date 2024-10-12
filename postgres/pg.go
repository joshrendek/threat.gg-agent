package postgres

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/jellydator/ttlcache/v3"

	"github.com/joshrendek/threat.gg-agent/honeypots"
	"github.com/rs/zerolog"

	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/joshrendek/threat.gg-agent/proto"

	uuid "github.com/satori/go.uuid"

	wire "github.com/jeroenrinzema/psql-wire"
)

var (
	logger = zerolog.New(os.Stdout).With().Caller().Str("postgres", "").Logger()
)

type honeypot struct {
	logger zerolog.Logger
}

func init() {
	honeypots.Register(&honeypot{logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", "postgres").Logger()})
}

func New() *honeypot {
	return &honeypot{logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", "postgres").Logger()}
}

func (h *honeypot) Name() string {
	return "ssh"
}

func (h *honeypot) Start() {
	auth := wire.ClearTextPassword(func(ctx context.Context, username, password string) (context.Context, bool, error) {
		//fmt.Println(username, password)
		guid := uuid.NewV4()

		remoteAddr := ctx.Value("remote_addr").(*net.TCPAddr)
		cacheKey := fmt.Sprintf("%s+%s", remoteAddr.IP.String(), username)
		cacheUUID, retrieved := honeypots.Cache.GetOrSet(cacheKey, guid.String(), ttlcache.WithTTL[string, string](ttlcache.DefaultTTL))
		if retrieved {
			guid, _ = uuid.FromString(cacheUUID.Value())
			println("re-using guid: ", guid.String())
		}

		ctx = context.WithValue(ctx, "guid", guid)

		lr := &proto.PostgresRequest{
			Guid:       guid.String(),
			Username:   username,
			Password:   password,
			RemoteAddr: remoteAddr.IP.String(),
		}
		if err := persistence.SavePostgresLogin(lr); err != nil {
			return ctx, false, err
		}
		return ctx, true, nil
	})
	server, _ := wire.NewServer(handler)
	server.Auth = auth
	port := os.Getenv("POSTGRES_PORT")
	if port == "" {
		port = "5432"

	}
	server.ListenAndServe(":" + port)
}

func handler(ctx context.Context, query string) (wire.PreparedStatements, error) {
	// simple checks
	query = strings.ToLower(query)
	uid := ctx.Value("guid").(uuid.UUID)
	q := &proto.QueryRequest{
		Guid:  uid.String(),
		Query: query,
	}

	go func(q *proto.QueryRequest) {
		err := persistence.SaveQuery(q)
		if err != nil {
			logger.Error().Err(err).Msg("error saving query")
		}
	}(q)

	if strings.Contains(query, "create role") {
		return wire.Prepared(wire.NewStatement(func(ctx context.Context, writer wire.DataWriter, parameters []wire.Parameter) error {
			return writer.Complete("CREATE ROLE")
		})), nil
	}

	resp, ok := responses[query]
	//litter.Dump(wire.ClientParameters(ctx))
	//litter.Dump(wire.ServerParameters(ctx))
	//litter.Dump(wire.TypeMap(ctx))
	// print out all values in ctx
	handle := func(ctx context.Context, writer wire.DataWriter, parameters []wire.Parameter) error {
		if !ok {
			return writer.Complete("OK")
		}
		for _, r := range resp.Rows {
			fmt.Println(r)
			x := []any{}
			for _, v := range r {
				x = append(x, v)
			}
			writer.Row(x) //nolint:errcheck
		}
		return writer.Complete("SELECT 2")
	}
	return wire.Prepared(wire.NewStatement(handle, wire.WithColumns(resp.Columns))), nil
}
