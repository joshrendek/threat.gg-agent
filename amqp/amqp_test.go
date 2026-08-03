package amqp

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	pb "github.com/joshrendek/threat.gg-agent/proto"
	amqp091 "github.com/rabbitmq/amqp091-go"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestRabbitMQGoClientCanDeclareBindAndPublish(t *testing.T) {
	oldSave := saveSession
	captured := make(chan *pb.AmqpSessionRequest, 1)
	saveSession = func(in *pb.AmqpSessionRequest) error { captured <- in; return nil }
	t.Cleanup(func() { saveSession = oldSave })
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			(&honeypot{logger: zerolog.Nop()}).handleConnection(conn)
		}
		close(done)
	}()
	conn, err := amqp091.DialConfig("amqp://alice:rabbit-secret@"+listener.Addr().String()+"/prod", amqp091.Config{Heartbeat: time.Second})
	require.NoError(t, err)
	channel, err := conn.Channel()
	require.NoError(t, err)
	require.NoError(t, channel.ExchangeDeclare("events", "topic", false, false, false, false, nil))
	queue, err := channel.QueueDeclare("jobs", false, false, false, false, nil)
	require.NoError(t, err)
	require.Equal(t, "jobs", queue.Name)
	require.NoError(t, channel.QueueBind("jobs", "jobs.created", "events", false, nil))
	require.NoError(t, channel.Confirm(false))
	require.NoError(t, channel.PublishWithContext(context.Background(), "events", "jobs.created", false, false, amqp091.Publishing{Body: []byte(`{"job":"backup"}`)}))
	require.NoError(t, conn.Close())
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("server did not stop")
	}
	select {
	case got := <-captured:
		require.Equal(t, "alice", got.Username)
		require.Equal(t, "rabbit-secret", got.Password)
		require.Equal(t, "prod", got.Vhost)
		require.Contains(t, strings.Join(got.Operations, "\n"), "BASIC_PUBLISH")
	case <-time.After(time.Second):
		t.Fatal("standard-client session was not persisted")
	}
}

func TestAMQP091NegotiatesCapturesCredentialsTopologyAndPublish(t *testing.T) {
	oldSave := saveSession
	captured := make(chan *pb.AmqpSessionRequest, 1)
	saveSession = func(in *pb.AmqpSessionRequest) error { captured <- in; return nil }
	t.Cleanup(func() { saveSession = oldSave })
	server, client := net.Pipe()
	h := &honeypot{logger: zerolog.Nop()}
	done := make(chan struct{})
	go func() { h.handleConnection(server); close(done) }()
	defer client.Close()

	_, err := client.Write([]byte("AMQP\x00\x00\x09\x01"))
	require.NoError(t, err)
	requireMethod(t, client, 10, 10)

	props := table(fieldString("product", "amqp091-go"), fieldString("version", "1.10.0"), fieldTable("capabilities", fieldBool("publisher_confirms", true)))
	startOK := append(props, byte(len("PLAIN")))
	startOK = append(startOK, "PLAIN"...)
	startOK = appendLongString(startOK, "\x00alice\x00rabbit-secret")
	startOK = append(startOK, byte(len("en_US")))
	startOK = append(startOK, "en_US"...)
	require.NoError(t, writeMethod(client, 0, 10, 11, startOK))
	requireMethod(t, client, 10, 30)
	require.NoError(t, writeMethod(client, 0, 10, 31, connectionTune()))
	open := appendShortString(nil, "/prod")
	open = appendShortString(open, "")
	open = append(open, 0)
	require.NoError(t, writeMethod(client, 0, 10, 40, open))
	requireMethod(t, client, 10, 41)

	require.NoError(t, writeMethod(client, 1, 20, 10, []byte{0, 0, 0, 0, 0}))
	requireMethod(t, client, 20, 11)
	exchange := []byte{0, 0}
	exchange = appendShortString(exchange, "events")
	exchange = appendShortString(exchange, "topic")
	exchange = append(exchange, 0)
	exchange = append(exchange, 0, 0, 0, 0)
	require.NoError(t, writeMethod(client, 1, 40, 10, exchange))
	requireMethod(t, client, 40, 11)
	queue := []byte{0, 0}
	queue = appendShortString(queue, "jobs")
	queue = append(queue, 0)
	queue = append(queue, 0, 0, 0, 0)
	require.NoError(t, writeMethod(client, 1, 50, 10, queue))
	requireMethod(t, client, 50, 11)
	bind := []byte{0, 0}
	bind = appendShortString(bind, "jobs")
	bind = appendShortString(bind, "events")
	bind = appendShortString(bind, "jobs.created")
	bind = append(bind, 0)
	bind = append(bind, 0, 0, 0, 0)
	require.NoError(t, writeMethod(client, 1, 50, 20, bind))
	requireMethod(t, client, 50, 21)
	require.NoError(t, writeMethod(client, 1, 85, 10, []byte{0}))
	requireMethod(t, client, 85, 11)

	publish := []byte{0, 0}
	publish = appendShortString(publish, "events")
	publish = appendShortString(publish, "jobs.created")
	publish = append(publish, 0)
	require.NoError(t, writeMethod(client, 1, 60, 40, publish))
	body := []byte(`{"job":"backup"}`)
	header := make([]byte, 14)
	binary.BigEndian.PutUint16(header[:2], 60)
	binary.BigEndian.PutUint64(header[4:12], uint64(len(body)))
	require.NoError(t, writeFrame(client, frame{typeID: 2, channel: 1, payload: header}))
	require.NoError(t, writeFrame(client, frame{typeID: 3, channel: 1, payload: body}))
	requireMethod(t, client, 60, 80)
	require.NoError(t, writeMethod(client, 0, 10, 50, nil))
	requireMethod(t, client, 10, 51)
	require.NoError(t, client.Close())
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("server did not stop")
	}

	select {
	case got := <-captured:
		require.Equal(t, "AMQP 0-9-1", got.Protocol)
		require.Equal(t, "alice", got.Username)
		require.Equal(t, "rabbit-secret", got.Password)
		require.Equal(t, "/prod", got.Vhost)
		require.Equal(t, "amqp091-go", got.ClientProperties["product"])
		joined := strings.Join(got.Operations, "\n")
		require.Contains(t, joined, `EXCHANGE_DECLARE exchange="events" type="topic"`)
		require.Contains(t, joined, `QUEUE_BIND queue="jobs" exchange="events" routing_key="jobs.created"`)
		require.Contains(t, joined, `BASIC_PUBLISH exchange="events" routing_key="jobs.created"`)
		require.Contains(t, joined, "eyJqb2IiOiJiYWNrdXAifQ==")
	case <-time.After(time.Second):
		t.Fatal("session was not persisted")
	}
}

func TestAMQP10GetsExplicitDowngradeAndCapture(t *testing.T) {
	oldSave := saveSession
	captured := make(chan *pb.AmqpSessionRequest, 1)
	saveSession = func(in *pb.AmqpSessionRequest) error { captured <- in; return nil }
	t.Cleanup(func() { saveSession = oldSave })
	server, client := net.Pipe()
	go (&honeypot{logger: zerolog.Nop()}).handleConnection(server)
	_, err := client.Write([]byte("AMQP\x00\x01\x00\x00"))
	require.NoError(t, err)
	header := make([]byte, 8)
	_, err = client.Read(header)
	require.NoError(t, err)
	require.Equal(t, []byte("AMQP\x00\x00\x09\x01"), header)
	require.Equal(t, "AMQP 1.0", (<-captured).Protocol)
}

func TestReadFrameRejectsOversizeAndBadTerminator(t *testing.T) {
	header := make([]byte, 7)
	binary.BigEndian.PutUint32(header[3:], maxFrameBytes+1)
	_, err := readFrame(strings.NewReader(string(header)))
	require.Error(t, err)
	bad := append([]byte{1, 0, 0, 0, 0, 0, 0}, 0)
	_, err = readFrame(strings.NewReader(string(bad)))
	require.Error(t, err)
}

func TestPublishCaptureCapKeepsBase64Valid(t *testing.T) {
	s := &session{publishes: map[uint16]*publish{1: {size: maxBodyCapture + 1024}}, operations: make([]string, 0, 1)}
	require.True(t, s.handleContentBody(frame{channel: 1, payload: make([]byte, maxBodyCapture+1024)}))
	require.Len(t, s.operations, 1)
	require.LessOrEqual(t, len(s.operations[0]), maxOperationBytes)
	encoded := strings.SplitN(s.operations[0], "body_base64=", 2)
	require.Len(t, encoded, 2)
	body, err := base64.StdEncoding.DecodeString(encoded[1])
	require.NoError(t, err)
	require.Len(t, body, maxBodyCapture)
}

func TestPublisherConfirmTagsArePerChannel(t *testing.T) {
	s := &session{deliveryTags: make(map[uint16]uint64)}
	server, client := net.Pipe()
	t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
	for _, channel := range []uint16{1, 1, 2} {
		done := make(chan struct{})
		go func(ch uint16) { s.ackPublish(server, ch); close(done) }(channel)
		f := requireMethod(t, client, 60, 80)
		require.Equal(t, channel, f.channel)
		<-done
		want := uint64(1)
		if channel == 1 && s.deliveryTags[channel] == 2 {
			want = 2
		}
		require.Equal(t, want, binary.BigEndian.Uint64(f.payload[4:12]))
	}
}

func TestNegotiatedHeartbeatIsEmitted(t *testing.T) {
	s := &session{heartbeatStop: make(chan struct{})}
	server, client := net.Pipe()
	t.Cleanup(func() { s.stopHeartbeat(); _ = server.Close(); _ = client.Close() })
	s.startHeartbeat(server, 1)
	require.NoError(t, client.SetReadDeadline(time.Now().Add(2*time.Second)))
	f, err := readFrame(client)
	require.NoError(t, err)
	require.Equal(t, byte(8), f.typeID)
}

func TestFieldTableSupportsStandardScalarsAndBoundsNesting(t *testing.T) {
	fields := appendShortString(nil, "byte")
	fields = append(fields, 'B', 7)
	fields = append(fields, appendShortString(nil, "timestamp")...)
	fields = append(fields, 'T', 0, 0, 0, 0, 0, 0, 0, 9)
	fields = append(fields, appendShortString(nil, "void")...)
	fields = append(fields, 'V')
	got, rest, err := parseTable(table(fields))
	require.NoError(t, err)
	require.Empty(t, rest)
	require.Equal(t, "7", got["byte"])
	require.Equal(t, "9", got["timestamp"])

	deep := table()
	for i := 0; i < maxTableDepth+1; i++ {
		deep = table(fieldTable("nested", deep[4:]))
	}
	_, _, err = parseTable(deep)
	require.ErrorContains(t, err, "too deep")
}

func TestPersistenceBackpressureDropsWithoutBlockingAndReleasesSlot(t *testing.T) {
	oldSlots, oldSave := persistenceSlots, saveSession
	t.Cleanup(func() { persistenceSlots, saveSession = oldSlots, oldSave })
	persistenceSlots = make(chan struct{}, 1)
	persistenceSlots <- struct{}{}
	called := make(chan struct{}, 1)
	saveSession = func(*pb.AmqpSessionRequest) error { called <- struct{}{}; return nil }
	start := time.Now()
	persist(&session{protocol: "AMQP 0-9-1"})
	require.Less(t, time.Since(start), 100*time.Millisecond)
	select {
	case <-called:
		t.Fatal("saturated persistence queue should drop the capture")
	default:
	}
	<-persistenceSlots
	persist(&session{protocol: "AMQP 0-9-1"})
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("available persistence slot was not used")
	}
	require.Eventually(t, func() bool { return len(persistenceSlots) == 0 }, time.Second, 10*time.Millisecond)
}

func requireMethod(t *testing.T, conn net.Conn, classID, methodID uint16) frame {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(time.Second)))
	f, err := readFrame(conn)
	require.NoError(t, err)
	require.Equal(t, byte(1), f.typeID)
	require.GreaterOrEqual(t, len(f.payload), 4)
	require.Equal(t, classID, binary.BigEndian.Uint16(f.payload[:2]))
	require.Equal(t, methodID, binary.BigEndian.Uint16(f.payload[2:4]))
	return f
}

func table(fields ...[]byte) []byte {
	body := []byte{}
	for _, field := range fields {
		body = append(body, field...)
	}
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, uint32(len(body)))
	return append(out, body...)
}
func fieldString(key, value string) []byte {
	out := appendShortString(nil, key)
	out = append(out, 'S')
	return appendLongString(out, value)
}
func fieldBool(key string, value bool) []byte {
	out := appendShortString(nil, key)
	out = append(out, 't')
	if value {
		out = append(out, 1)
	} else {
		out = append(out, 0)
	}
	return out
}
func fieldTable(key string, fields ...[]byte) []byte {
	out := appendShortString(nil, key)
	out = append(out, 'F')
	return append(out, table(fields...)...)
}
