package main

import (
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/joshrendek/threat.gg-agent/honeypots"
	"github.com/joshrendek/threat.gg-agent/icsprobe"
)

// The ICS profile runs the passive port probe ALONGSIDE real ICS emulators, and
// they draw from the same pool of industrial ports. If both claim one, the
// second to start loses the bind -- and the failure is close to invisible: the
// node stays healthy, the port still shows as listening, traffic is still
// captured by whichever won, and the emulator is simply absent.
//
// That is exactly what happened when s7comm shipped: icsprobe still listed 102,
// registers first, and would have taken the port the S7-300 emulator exists to
// serve.
//
// This test is the guard. Every ICS honeypot that binds a fixed industrial port
// must be listed here, so the collision is caught at build time rather than by
// noticing months later that an emulator never saw traffic.
func TestProbePortsDoNotCollideWithRealHoneypots(t *testing.T) {
	// port -> the honeypot that owns it. Add an entry when a new ICS emulator
	// claims a port.
	owned := map[int]string{
		102: "s7comm",
		502: "modbus",
	}

	probePorts := icsprobe.DefaultPorts()
	if len(probePorts) == 0 {
		t.Fatal("icsprobe reported no default ports")
	}
	for _, p := range probePorts {
		if owner, taken := owned[p]; taken {
			t.Errorf("icsprobe still probes port %d, which belongs to the %q honeypot. "+
				"Both are in ProfileICS, so they will collide: the probe registers first, "+
				"wins the bind, and the emulator silently never starts while the node still "+
				"looks healthy. Remove %d from icsprobe's defaults.", p, owner, p)
		}
	}
}

// Every port an ICS honeypot owns must actually be reachable through the ics
// profile -- otherwise removing it from the probe just loses coverage.
func TestOwnedICSPortsAreServedBySomethingInTheICSProfile(t *testing.T) {
	names, err := honeypots.ProfileNames(honeypots.ProfileICS, catalog())
	if err != nil {
		t.Fatalf("resolving the ics profile: %v", err)
	}
	joined := strings.Join(names, ",")
	if !strings.Contains(joined, "s7comm") {
		t.Errorf("ProfileICS = %v; s7comm must be present or port 102 is served by nothing "+
			"after being removed from the probe", names)
	}
	if !strings.Contains(joined, "modbus") {
		t.Errorf("ProfileICS = %v; modbus must be present or port 502 is served by nothing "+
			"after being removed from the probe", names)
	}
	if !strings.Contains(joined, "icsprobe") {
		t.Errorf("ProfileICS = %v; icsprobe must be present to cover the ports no emulator owns yet", names)
	}
}

// Guard the env override too: an operator setting ICS_PROBE_PORTS back to a
// list containing an owned port reintroduces the collision at runtime.
func TestProbeEnvOverrideCannotReclaimAnOwnedPort(t *testing.T) {
	os.Setenv("ICS_PROBE_PORTS", "102,502")
	defer os.Unsetenv("ICS_PROBE_PORTS")

	got := icsprobe.PortsFromEnv()
	for _, p := range got {
		if p == 102 {
			t.Errorf("ICS_PROBE_PORTS=%q yielded port 102, which s7comm owns; the probe must "+
				"drop owned ports rather than fight the emulator for the bind",
				strconv.Quote("102,502"))
		}
		if p == 502 {
			t.Errorf("ICS_PROBE_PORTS=%q yielded port 502, which modbus owns; the probe must "+
				"drop owned ports rather than fight the emulator for the bind",
				strconv.Quote("102,502"))
		}
	}
}
