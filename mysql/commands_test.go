package mysql

import (
	"bytes"
	"strings"
	"testing"
)

func TestHandleComQuery_Version(t *testing.T) {
	var buf bytes.Buffer
	_, err := handleComQuery(&buf, 1, "SELECT @@version")
	if err != nil {
		t.Fatalf("handleComQuery failed: %v", err)
	}
	result := buf.String()
	if !strings.Contains(result, "8.0.35") {
		t.Fatalf("expected version in response, got %q", result)
	}
}

func TestHandleComQuery_VersionComment(t *testing.T) {
	var buf bytes.Buffer
	_, err := handleComQuery(&buf, 1, "select @@version_comment")
	if err != nil {
		t.Fatalf("handleComQuery failed: %v", err)
	}
	result := buf.String()
	if !strings.Contains(result, "Ubuntu") {
		t.Fatalf("expected 'Ubuntu' in response, got %q", result)
	}
}

func TestHandleComQuery_ShowDatabases(t *testing.T) {
	var buf bytes.Buffer
	_, err := handleComQuery(&buf, 1, "SHOW DATABASES")
	if err != nil {
		t.Fatalf("handleComQuery failed: %v", err)
	}
	result := buf.String()
	if !strings.Contains(result, "production") {
		t.Fatalf("expected 'production' in response, got %q", result)
	}
	if !strings.Contains(result, "information_schema") {
		t.Fatalf("expected 'information_schema' in response, got %q", result)
	}
}

func TestHandleComQuery_ShowTables(t *testing.T) {
	var buf bytes.Buffer
	_, err := handleComQuery(&buf, 1, "SHOW TABLES")
	if err != nil {
		t.Fatalf("handleComQuery failed: %v", err)
	}
	result := buf.String()
	if !strings.Contains(result, "users") {
		t.Fatalf("expected 'users' in response, got %q", result)
	}
}

func TestHandleComQuery_UnknownSelect(t *testing.T) {
	var buf bytes.Buffer
	_, err := handleComQuery(&buf, 1, "SELECT * FROM nonexistent")
	if err != nil {
		t.Fatalf("handleComQuery failed: %v", err)
	}
	// Should return empty result set (no error)
	if buf.Len() == 0 {
		t.Fatal("expected non-empty response for unknown SELECT")
	}
}

func TestHandleComQuery_DML(t *testing.T) {
	var buf bytes.Buffer
	_, err := handleComQuery(&buf, 1, "INSERT INTO users VALUES (1, 'test')")
	if err != nil {
		t.Fatalf("handleComQuery failed: %v", err)
	}
	// Should contain OK marker (0x00)
	data := buf.Bytes()
	if len(data) < 5 {
		t.Fatal("response too short")
	}
	if data[4] != 0x00 {
		t.Fatalf("expected OK marker 0x00 for DML, got 0x%02x", data[4])
	}
}

func TestHandleComQuery_DDL(t *testing.T) {
	var buf bytes.Buffer
	_, err := handleComQuery(&buf, 1, "DROP TABLE IF EXISTS test")
	if err != nil {
		t.Fatalf("handleComQuery failed: %v", err)
	}
	data := buf.Bytes()
	if len(data) < 5 || data[4] != 0x00 {
		t.Fatal("expected OK packet for DDL")
	}
}

func TestHandleComQuery_SetCommand(t *testing.T) {
	var buf bytes.Buffer
	_, err := handleComQuery(&buf, 1, "SET NAMES utf8mb4")
	if err != nil {
		t.Fatalf("handleComQuery failed: %v", err)
	}
	data := buf.Bytes()
	if len(data) < 5 || data[4] != 0x00 {
		t.Fatal("expected OK packet for SET")
	}
}

func TestHandleComPing(t *testing.T) {
	var buf bytes.Buffer
	err := handleComPing(&buf, 1)
	if err != nil {
		t.Fatalf("handleComPing failed: %v", err)
	}
	data := buf.Bytes()
	if len(data) < 5 || data[4] != 0x00 {
		t.Fatal("expected OK packet for PING")
	}
}

func TestHandleComInitDB(t *testing.T) {
	var buf bytes.Buffer
	err := handleComInitDB(&buf, 1)
	if err != nil {
		t.Fatalf("handleComInitDB failed: %v", err)
	}
	data := buf.Bytes()
	if len(data) < 5 || data[4] != 0x00 {
		t.Fatal("expected OK packet for INIT_DB")
	}
}

func TestHandleComStatistics(t *testing.T) {
	var buf bytes.Buffer
	err := handleComStatistics(&buf, 1)
	if err != nil {
		t.Fatalf("handleComStatistics failed: %v", err)
	}
	result := buf.String()
	if !strings.Contains(result, "Uptime") {
		t.Fatalf("expected 'Uptime' in statistics response, got %q", result)
	}
}

func TestHandleComQuery_CaseInsensitive(t *testing.T) {
	var buf1 bytes.Buffer
	_, err := handleComQuery(&buf1, 1, "SHOW DATABASES")
	if err != nil {
		t.Fatalf("handleComQuery failed: %v", err)
	}

	var buf2 bytes.Buffer
	_, err = handleComQuery(&buf2, 1, "show databases")
	if err != nil {
		t.Fatalf("handleComQuery failed: %v", err)
	}

	if buf1.String() != buf2.String() {
		t.Fatal("expected case-insensitive matching to produce same results")
	}
}

func TestHandleComQuery_SelectDatabase(t *testing.T) {
	var buf bytes.Buffer
	_, err := handleComQuery(&buf, 1, "SELECT database()")
	if err != nil {
		t.Fatalf("handleComQuery failed: %v", err)
	}
	result := buf.String()
	if !strings.Contains(result, "production") {
		t.Fatalf("expected 'production' in response, got %q", result)
	}
}
