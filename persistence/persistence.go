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
	grpcTarget := "grpc.threat.gg:443"
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

func Connect(version string) error {
	ctx := context.Background()
	ctx = metadata.NewOutgoingContext(ctx, connMetadata)
	_, err := honeypotClient.Connect(ctx, &proto.ConnectRequest{Version: version})
	return err
}

func SaveFTPLogin(in *proto.FtpRequest) error {
	ctx := context.Background()
	ctx = metadata.NewOutgoingContext(ctx, connMetadata)
	_, err := honeypotClient.SaveFtpLogin(ctx, in)
	return err
}

func SavePostgresLogin(in *proto.PostgresRequest) error {
	ctx := context.Background()
	ctx = metadata.NewOutgoingContext(ctx, connMetadata)
	_, err := honeypotClient.SavePostgresLogin(ctx, in)
	return err

}

func SaveSshLogin(in *proto.SshLoginRequest) error {
	ctx := context.Background()
	ctx = metadata.NewOutgoingContext(ctx, connMetadata)
	_, err := honeypotClient.SaveSshLogin(ctx, in)
	return err
}

func SaveQuery(in *proto.QueryRequest) error {
	ctx := context.Background()
	ctx = metadata.NewOutgoingContext(ctx, connMetadata)
	_, err := honeypotClient.SaveQuery(ctx, in)
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

func SaveOpenclawConnect(in *proto.OpenclawRequest) error {
	ctx := context.Background()
	ctx = metadata.NewOutgoingContext(ctx, connMetadata)
	_, err := honeypotClient.SaveOpenclawConnect(ctx, in)
	return err
}

func SaveKafkaConnect(in *proto.KafkaRequest) error {
	ctx := context.Background()
	ctx = metadata.NewOutgoingContext(ctx, connMetadata)
	_, err := honeypotClient.SaveKafkaConnect(ctx, in)
	return err
}

func SaveKafkaApiRequest(in *proto.KafkaApiRequest) error {
	ctx := context.Background()
	ctx = metadata.NewOutgoingContext(ctx, connMetadata)
	_, err := honeypotClient.SaveKafkaApiRequest(ctx, in)
	return err
}

func SaveMysqlLogin(in *proto.MysqlRequest) error {
	ctx := context.Background()
	ctx = metadata.NewOutgoingContext(ctx, connMetadata)
	_, err := honeypotClient.SaveMysqlLogin(ctx, in)
	return err
}

func SaveRedisConnect(in *proto.RedisConnectRequest) error {
	ctx := context.Background()
	ctx = metadata.NewOutgoingContext(ctx, connMetadata)
	_, err := honeypotClient.SaveRedisConnect(ctx, in)
	return err
}

func SaveRedisCommand(in *proto.RedisCommandRequest) error {
	ctx := context.Background()
	ctx = metadata.NewOutgoingContext(ctx, connMetadata)
	_, err := honeypotClient.SaveRedisCommand(ctx, in)
	return err
}

func SaveDockerRequest(in *proto.DockerRequest) error {
	ctx := context.Background()
	ctx = metadata.NewOutgoingContext(ctx, connMetadata)
	_, err := honeypotClient.SaveDockerRequest(ctx, in)
	return err
}

func GetCommandResponse(in *proto.CommandRequest) (*proto.CommandResponse, error) {
	ctx := context.Background()
	ctx = metadata.NewOutgoingContext(ctx, connMetadata)
	return honeypotClient.GetCommandResponse(ctx, in)
}
