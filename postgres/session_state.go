package postgres

import (
	"strings"
	"sync"
	"time"
)

const (
	maxPostgresSessions = 4096
	postgresSessionTTL  = 30 * time.Minute
)

type postgresSessionState struct {
	output    string
	hasOutput bool
	updatedAt time.Time
}

var postgresSessions = struct {
	sync.Mutex
	items map[string]postgresSessionState
}{items: make(map[string]postgresSessionState)}

func statefulPostgresResponse(sessionID, query string) (structuredPostgresResponse, bool) {
	normalized := strings.TrimSpace(strings.TrimSuffix(query, ";"))
	switch {
	case strings.HasPrefix(normalized, "create temp table") && strings.Contains(normalized, "_pgenv"):
		touchPostgresSession(sessionID, "", false)
		return postgresTagResponse("CREATE TABLE"), true
	case strings.HasPrefix(normalized, "truncate") && strings.Contains(normalized, "_pgenv"):
		touchPostgresSession(sessionID, "", false)
		return postgresTagResponse("TRUNCATE TABLE"), true
	case strings.HasPrefix(normalized, "drop table") && strings.Contains(normalized, "_pgenv"):
		deletePostgresSession(sessionID)
		return postgresTagResponse("DROP TABLE"), true
	case strings.HasPrefix(normalized, "copy") && strings.Contains(normalized, "_pgenv") && strings.Contains(normalized, "from program"):
		output := fakeProgramOutput(normalized)
		touchPostgresSession(sessionID, output, true)
		return postgresTagResponse("COPY 1"), true
	case strings.HasPrefix(normalized, "select") && strings.Contains(normalized, " from _pgenv"):
		output, exists := postgresSessionOutput(sessionID)
		response := structuredPostgresResponse{
			Columns: []postgresResponseColumn{{Name: "o", Type: "text"}},
			Tag:     "SELECT 0",
		}
		if exists {
			response.Rows = [][]any{{output}}
			response.Tag = "SELECT 1"
		}
		return response, true
	default:
		return structuredPostgresResponse{}, false
	}
}

func postgresTagResponse(tag string) structuredPostgresResponse {
	return structuredPostgresResponse{Tag: tag}
}

func fakeProgramOutput(program string) string {
	switch {
	case strings.Contains(program, "/.dockerenv"):
		return "docker"
	case strings.Contains(program, "docker.sock"):
		return "no"
	case strings.Contains(program, "/proc/meminfo") || strings.Contains(program, "memtotal"):
		return "MemTotal:        2048000 kB"
	case strings.Contains(program, "whoami"):
		return "postgres"
	case strings.Contains(program, "hostname"):
		return "db-primary"
	case strings.Contains(program, "uname"):
		return "Linux db-primary 5.15.0-91-generic x86_64 GNU/Linux"
	case strings.Contains(program, " id") || strings.Contains(program, "'id"):
		return "uid=999(postgres) gid=999(postgres) groups=999(postgres)"
	default:
		return "permission denied"
	}
}

func touchPostgresSession(sessionID, output string, hasOutput bool) {
	postgresSessions.Lock()
	defer postgresSessions.Unlock()
	now := time.Now()
	prunePostgresSessions(now)
	state := postgresSessions.items[sessionID]
	state.output = output
	state.hasOutput = hasOutput
	state.updatedAt = now
	postgresSessions.items[sessionID] = state
	if len(postgresSessions.items) <= maxPostgresSessions {
		return
	}
	var oldestID string
	var oldestTime time.Time
	for id, candidate := range postgresSessions.items {
		if oldestID == "" || candidate.updatedAt.Before(oldestTime) {
			oldestID, oldestTime = id, candidate.updatedAt
		}
	}
	delete(postgresSessions.items, oldestID)
}

func postgresSessionOutput(sessionID string) (string, bool) {
	postgresSessions.Lock()
	defer postgresSessions.Unlock()
	state, ok := postgresSessions.items[sessionID]
	if !ok || time.Since(state.updatedAt) > postgresSessionTTL {
		delete(postgresSessions.items, sessionID)
		return "", false
	}
	state.updatedAt = time.Now()
	postgresSessions.items[sessionID] = state
	return state.output, state.hasOutput
}

func deletePostgresSession(sessionID string) {
	postgresSessions.Lock()
	delete(postgresSessions.items, sessionID)
	postgresSessions.Unlock()
}

func prunePostgresSessions(now time.Time) {
	for id, state := range postgresSessions.items {
		if now.Sub(state.updatedAt) > postgresSessionTTL {
			delete(postgresSessions.items, id)
		}
	}
}
