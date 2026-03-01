package ldap

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	ldapmsg "github.com/lor00x/goldap/message"
	"github.com/rs/zerolog"
	uuid "github.com/satori/go.uuid"
	ldapserver "github.com/vjeantet/ldapserver"

	"github.com/joshrendek/threat.gg-agent/honeypots"
	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/joshrendek/threat.gg-agent/proto"
)

const (
	defaultPort     = "389"
	maxOpsPerConn   = 200
	maxFilterLength = 4096
)

var _ honeypots.Honeypot = &honeypot{}

var logger = zerolog.New(os.Stdout).With().Caller().Str("honeypot", "ldap").Logger()

type honeypot struct {
	port string
}

type session struct {
	guid     string
	remoteIP string
	mu       sync.Mutex
	opCount  int
}

var sessions sync.Map

func New() honeypots.Honeypot {
	port := os.Getenv("LDAP_HONEYPOT_PORT")
	if port == "" {
		port = defaultPort
	}
	return &honeypot{port: port}
}

func (h *honeypot) Name() string {
	return "ldap"
}

func (h *honeypot) Start() {
	server := ldapserver.NewServer()

	routes := ldapserver.NewRouteMux()
	routes.Bind(handleBind)
	routes.Search(handleSearch)
	routes.NotFound(handleNotFound)

	server.Handle(routes)

	logger.Info().Str("port", h.port).Msg("starting LDAP honeypot")
	if err := server.ListenAndServe(":" + h.port); err != nil {
		logger.Error().Err(err).Msg("LDAP honeypot listen error")
	}
}

func getOrCreateSession(conn net.Conn) *session {
	addr := conn.RemoteAddr().String()
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		host = addr
	}

	if s, ok := sessions.Load(addr); ok {
		return s.(*session)
	}

	s := &session{
		guid:     uuid.NewV4().String(),
		remoteIP: host,
	}
	actual, _ := sessions.LoadOrStore(addr, s)
	return actual.(*session)
}

func handleBind(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	conn := m.Client.GetConn()
	sess := getOrCreateSession(conn)

	sess.mu.Lock()
	sess.opCount++
	if sess.opCount > maxOpsPerConn {
		sess.mu.Unlock()
		res := ldapserver.NewBindResponse(ldapserver.LDAPResultUnwillingToPerform)
		w.Write(res)
		return
	}
	sess.mu.Unlock()

	r := m.GetBindRequest()
	bindDN := string(r.Name())

	authType := r.AuthenticationChoice()
	password := ""
	saslMechanism := ""

	if authType == "simple" {
		password = string(r.AuthenticationSimple())
	} else if authType == "sasl" {
		// For SASL binds, we cannot extract a simple password.
		// Try to get the SASL mechanism name from the credentials.
		saslMechanism = "unknown"
	}

	if bindDN == "" && password == "" && authType == "simple" {
		authType = "anonymous"
	}

	logger.Info().
		Str("remote", sess.remoteIP).
		Str("bind_dn", bindDN).
		Str("auth_type", authType).
		Msg("LDAP bind attempt")

	go func() {
		req := &proto.LdapBindRequest{
			RemoteAddr:    sess.remoteIP,
			Guid:          sess.guid,
			BindDn:        bindDN,
			Password:      password,
			AuthType:      authType,
			SaslMechanism: saslMechanism,
		}
		if err := persistence.SaveLdapBind(req); err != nil {
			logger.Error().Err(err).Msg("error saving ldap bind")
		}
	}()

	res := ldapserver.NewBindResponse(ldapserver.LDAPResultSuccess)
	w.Write(res)
}

func handleSearch(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	conn := m.Client.GetConn()
	sess := getOrCreateSession(conn)

	sess.mu.Lock()
	sess.opCount++
	if sess.opCount > maxOpsPerConn {
		sess.mu.Unlock()
		res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultUnwillingToPerform)
		w.Write(res)
		return
	}
	sess.mu.Unlock()

	r := m.GetSearchRequest()
	baseDN := string(r.BaseObject())
	filter := r.FilterString()
	scope := scopeToString(int(r.Scope()))

	// Collect requested attributes
	attrs := make([]string, 0)
	for _, attr := range r.Attributes() {
		attrs = append(attrs, string(attr))
	}
	attrStr := strings.Join(attrs, ",")

	// Truncate long filters
	if len(filter) > maxFilterLength {
		filter = filter[:maxFilterLength]
	}

	logger.Info().
		Str("remote", sess.remoteIP).
		Str("base_dn", baseDN).
		Str("filter", filter).
		Str("scope", scope).
		Msg("LDAP search request")

	go func() {
		req := &proto.LdapSearchRequest{
			Guid:       sess.guid,
			BaseDn:     baseDN,
			Filter:     filter,
			Scope:      scope,
			Attributes: attrStr,
		}
		if err := persistence.SaveLdapSearch(req); err != nil {
			logger.Error().Err(err).Msg("error saving ldap search")
		}
	}()

	// RootDSE query: empty baseDN + base scope
	if baseDN == "" && scope == "base" {
		entry := getRootDSE()
		e := ldapserver.NewSearchResultEntry(entry.dn)
		for k, vals := range entry.attributes {
			for _, v := range vals {
				e.AddAttribute(ldapmsg.AttributeDescription(k), ldapmsg.AttributeValue(v))
			}
		}
		w.Write(e)
		res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess)
		w.Write(res)
		return
	}

	// Check for JNDI-style exploit paths
	if isJNDIPath(baseDN) {
		logger.Warn().
			Str("remote", sess.remoteIP).
			Str("base_dn", baseDN).
			Msg("JNDI exploit attempt detected")
		res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess)
		w.Write(res)
		return
	}

	// Search fake directory
	entries := searchEntries(baseDN, filter, scope)
	for _, entry := range entries {
		e := ldapserver.NewSearchResultEntry(entry.dn)
		for k, vals := range entry.attributes {
			for _, v := range vals {
				e.AddAttribute(ldapmsg.AttributeDescription(k), ldapmsg.AttributeValue(v))
			}
		}
		w.Write(e)
	}

	res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess)
	w.Write(res)
}

func handleNotFound(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	// Silently handle unsupported operations
}

func scopeToString(scope int) string {
	switch scope {
	case 0:
		return "base"
	case 1:
		return "one"
	case 2:
		return "sub"
	default:
		return fmt.Sprintf("unknown(%d)", scope)
	}
}

func isJNDIPath(baseDN string) bool {
	lower := strings.ToLower(baseDN)
	return strings.Contains(lower, "/exploit") ||
		strings.Contains(lower, "/basic/") ||
		strings.Contains(lower, "/command/") ||
		strings.Contains(lower, "javax.naming") ||
		strings.HasPrefix(lower, "ldap://") ||
		strings.HasPrefix(lower, "rmi://")
}
