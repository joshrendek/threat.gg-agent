package redis

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// parseCommand reads one RESP command from the reader.
// Supports both inline commands ("PING\r\n") and RESP arrays ("*1\r\n$4\r\nPING\r\n").
func parseCommand(reader *bufio.Reader) ([]string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")

	if len(line) == 0 {
		return nil, fmt.Errorf("empty command")
	}

	// RESP array
	if line[0] == '*' {
		count, err := strconv.Atoi(line[1:])
		if err != nil || count < 0 {
			return nil, fmt.Errorf("invalid array count: %s", line)
		}
		args := make([]string, 0, count)
		for i := 0; i < count; i++ {
			s, err := readBulkString(reader)
			if err != nil {
				return nil, err
			}
			args = append(args, s)
		}
		return args, nil
	}

	// Inline command
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return nil, fmt.Errorf("empty inline command")
	}
	return parts, nil
}

// readBulkString reads a RESP bulk string ($len\r\ndata\r\n).
func readBulkString(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")

	if len(line) == 0 || line[0] != '$' {
		return "", fmt.Errorf("expected bulk string, got: %s", line)
	}

	length, err := strconv.Atoi(line[1:])
	if err != nil {
		return "", fmt.Errorf("invalid bulk string length: %s", line)
	}

	if length < 0 {
		return "", nil // nil bulk string
	}

	// Cap bulk string reads at 64KB to prevent memory exhaustion
	if length > 65536 {
		length = 65536
	}

	data := make([]byte, length+2) // +2 for trailing \r\n
	_, err = io.ReadFull(reader, data)
	if err != nil {
		return "", err
	}

	return string(data[:length]), nil
}

func writeSimpleString(w io.Writer, s string) error {
	_, err := fmt.Fprintf(w, "+%s\r\n", s)
	return err
}

func writeError(w io.Writer, msg string) error {
	_, err := fmt.Fprintf(w, "-ERR %s\r\n", msg)
	return err
}

func writeInteger(w io.Writer, n int64) error {
	_, err := fmt.Fprintf(w, ":%d\r\n", n)
	return err
}

func writeBulkString(w io.Writer, s string) error {
	_, err := fmt.Fprintf(w, "$%d\r\n%s\r\n", len(s), s)
	return err
}

func writeNullBulkString(w io.Writer) error {
	_, err := fmt.Fprint(w, "$-1\r\n")
	return err
}

func writeArray(w io.Writer, items []string) error {
	if _, err := fmt.Fprintf(w, "*%d\r\n", len(items)); err != nil {
		return err
	}
	for _, item := range items {
		if err := writeBulkString(w, item); err != nil {
			return err
		}
	}
	return nil
}
