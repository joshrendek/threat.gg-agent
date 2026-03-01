package redis

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func TestParseCommand_RESPArray(t *testing.T) {
	input := "*3\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nbar\r\n"
	reader := bufio.NewReader(strings.NewReader(input))

	args, err := parseCommand(reader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(args) != 3 {
		t.Fatalf("expected 3 args, got %d", len(args))
	}
	if args[0] != "SET" || args[1] != "foo" || args[2] != "bar" {
		t.Fatalf("unexpected args: %v", args)
	}
}

func TestParseCommand_InlineCommand(t *testing.T) {
	input := "PING\r\n"
	reader := bufio.NewReader(strings.NewReader(input))

	args, err := parseCommand(reader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(args) != 1 || args[0] != "PING" {
		t.Fatalf("unexpected args: %v", args)
	}
}

func TestParseCommand_InlineWithArgs(t *testing.T) {
	input := "GET mykey\r\n"
	reader := bufio.NewReader(strings.NewReader(input))

	args, err := parseCommand(reader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(args) != 2 || args[0] != "GET" || args[1] != "mykey" {
		t.Fatalf("unexpected args: %v", args)
	}
}

func TestParseCommand_EmptyBulkString(t *testing.T) {
	input := "*1\r\n$0\r\n\r\n"
	reader := bufio.NewReader(strings.NewReader(input))

	args, err := parseCommand(reader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(args) != 1 || args[0] != "" {
		t.Fatalf("expected empty string arg, got: %v", args)
	}
}

func TestParseCommand_NilBulkString(t *testing.T) {
	input := "*1\r\n$-1\r\n"
	reader := bufio.NewReader(strings.NewReader(input))

	args, err := parseCommand(reader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(args) != 1 || args[0] != "" {
		t.Fatalf("expected empty string for nil bulk, got: %v", args)
	}
}

func TestWriteSimpleString(t *testing.T) {
	var buf bytes.Buffer
	writeSimpleString(&buf, "OK")
	if buf.String() != "+OK\r\n" {
		t.Fatalf("expected +OK\\r\\n, got %q", buf.String())
	}
}

func TestWriteError(t *testing.T) {
	var buf bytes.Buffer
	writeError(&buf, "unknown command")
	if buf.String() != "-ERR unknown command\r\n" {
		t.Fatalf("expected error string, got %q", buf.String())
	}
}

func TestWriteInteger(t *testing.T) {
	var buf bytes.Buffer
	writeInteger(&buf, 42)
	if buf.String() != ":42\r\n" {
		t.Fatalf("expected :42\\r\\n, got %q", buf.String())
	}
}

func TestWriteBulkString(t *testing.T) {
	var buf bytes.Buffer
	writeBulkString(&buf, "hello")
	if buf.String() != "$5\r\nhello\r\n" {
		t.Fatalf("expected bulk string, got %q", buf.String())
	}
}

func TestWriteNullBulkString(t *testing.T) {
	var buf bytes.Buffer
	writeNullBulkString(&buf)
	if buf.String() != "$-1\r\n" {
		t.Fatalf("expected null bulk string, got %q", buf.String())
	}
}

func TestWriteArray(t *testing.T) {
	var buf bytes.Buffer
	writeArray(&buf, []string{"foo", "bar"})
	expected := "*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n"
	if buf.String() != expected {
		t.Fatalf("expected %q, got %q", expected, buf.String())
	}
}

func TestWriteEmptyArray(t *testing.T) {
	var buf bytes.Buffer
	writeArray(&buf, []string{})
	if buf.String() != "*0\r\n" {
		t.Fatalf("expected empty array, got %q", buf.String())
	}
}
