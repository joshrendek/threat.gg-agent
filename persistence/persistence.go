package persistence

import (
	"context"
	"crypto/tls"
	"net/http"
	"os"
	"strings"

	"github.com/joshrendek/threat.gg-agent/proto"
	"google.golang.org/grpc/metadata"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/rs/zerolog"
)

var (
	client         = &http.Client{}
	logger         = zerolog.New(os.Stdout).With().Caller().Str("persistence", "").Logger()
	conn           *grpc.ClientConn
	connMetadata   = metadata.New(map[string]string{"authorization": os.Getenv("API_KEY")})
	honeypotClient proto.HoneypotClient
)

func Setup() error {
	config := &tls.Config{
		InsecureSkipVerify: false,
	}
	var err error
	grpcTarget := "api.threat.gg"
	if os.Getenv("GO_ENV") == "development" {
		grpcTarget = ":50051"
		config.InsecureSkipVerify = true
	}
	conn, err = grpc.Dial(grpcTarget, grpc.WithTransportCredentials(credentials.NewTLS(config)))
	if err != nil {
		return err
	}

	honeypotClient = proto.NewHoneypotClient(conn)

	return nil
}

func HttpToMap(in map[string][]string) map[string]string {
	ret := map[string]string{}
	for k, v := range in {
		ret[k] = strings.Join(v, ",")
	}
	return ret
}

func Connect() error {
	ctx := context.Background()
	ctx = metadata.NewOutgoingContext(ctx, connMetadata)
	_, err := honeypotClient.Connect(ctx, &proto.ConnectRequest{})
	return err
}

func SaveFTPLogin(in *proto.FtpRequest) error {
	ctx := context.Background()
	ctx = metadata.NewOutgoingContext(ctx, connMetadata)
	_, err := honeypotClient.SaveFtpLogin(ctx, in)
	return err
}

func SaveSshLogin(in *proto.SshLoginRequest) error {
	ctx := context.Background()
	ctx = metadata.NewOutgoingContext(ctx, connMetadata)
	_, err := honeypotClient.SaveSshLogin(ctx, in)
	return err
}

func SaveElasticRequest(in *proto.ElasticsearchRequest) error {
	ctx := context.Background()
	ctx = metadata.NewOutgoingContext(ctx, connMetadata)
	_, err := honeypotClient.SaveElasticsearch(ctx, in)
	return err
}

func SaveHTTPRequest(in *proto.HttpRequest) error {
	ctx := context.Background()
	ctx = metadata.NewOutgoingContext(ctx, connMetadata)
	_, err := honeypotClient.SaveHttp(ctx, in)
	return err
}

func SaveShellCommand(in *proto.ShellCommandRequest) error {
	ctx := context.Background()
	ctx = metadata.NewOutgoingContext(ctx, connMetadata)
	_, err := honeypotClient.SaveShellCommand(ctx, in)
	return err
}

func GetCommandResponse(in *proto.CommandRequest) (*proto.CommandResponse, error) {
	ctx := context.Background()
	ctx = metadata.NewOutgoingContext(ctx, connMetadata)
	return honeypotClient.GetCommandResponse(ctx, in)
}
