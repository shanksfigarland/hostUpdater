package hostsync

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseHostsLinesDropsIPHostnameFallback(t *testing.T) {
	output := `
10.10.10.10 dc01.corp.local
10.10.10.20 10.10.10.20
`
	entries := Parse(output, "smb")
	if len(entries) != 1 {
		t.Fatalf("len(Parse()) = %d, want 1: %#v", len(entries), entries)
	}
	if got := strings.Join(entries[0].Names(), " "); got != "dc01.corp.local dc01" {
		t.Fatalf("Names() = %q", got)
	}
}

func TestParseLDAPBanner(t *testing.T) {
	output := `LDAP 10.10.10.10 389 DC01 [*] Windows Server (name:DC01) (domain:corp.local)`
	entries := Parse(output, "ldap")
	if len(entries) != 1 || entries[0].Hostname != "dc01" || entries[0].Domain != "corp.local" {
		t.Fatalf("Parse() = %#v", entries)
	}
}

func TestMergeEntriesPrefersLDAP(t *testing.T) {
	entries := MergeEntries(
		[]Entry{{IP: "10.10.10.10", Hostname: "dc01", Source: "smb"}},
		[]Entry{{IP: "10.10.10.10", Hostname: "dc01", Domain: "corp.local", Source: "ldap"}},
	)
	if len(entries) != 1 || entries[0].Source != "ldap" {
		t.Fatalf("MergeEntries() = %#v", entries)
	}
}

func TestUpdateHostsPreservesManualLinesAndReplacesManagedBlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	initial := "127.0.0.1 localhost\n# BEGIN NXC-HOSTSYNC MANAGED BLOCK\n10.0.0.1 old.local\n# END NXC-HOSTSYNC MANAGED BLOCK\n"
	if err := os.WriteFile(path, []byte(initial), 0o644); err != nil {
		t.Fatal(err)
	}
	next, err := UpdateHosts([]Entry{{IP: "10.10.10.10", Hostname: "dc01", Domain: "corp.local", Source: "ldap"}}, Options{HostsPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(next, "127.0.0.1 localhost") || strings.Contains(next, "old.local") || !strings.Contains(next, "dc01.corp.local dc01") {
		t.Fatalf("UpdateHosts() output:\n%s", next)
	}
}

func TestDryRunDoesNotWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(path, []byte("127.0.0.1 localhost\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := UpdateHosts([]Entry{{IP: "10.10.10.10", Hostname: "dc01", Domain: "corp.local", Source: "ldap"}}, Options{HostsPath: path, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "dc01") {
		t.Fatal("dry run modified hosts file")
	}
}

func TestUndoRestoresBaselineAndBacksUpCurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	original := "127.0.0.1 localhost\n"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := UpdateHosts([]Entry{{IP: "10.10.10.10", Hostname: "dc01", Domain: "corp.local", Source: "ldap"}}, Options{HostsPath: path, Backup: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(BaselinePath(path)); err != nil {
		t.Fatalf("baseline missing: %v", err)
	}
	_, restorePoint, err := Undo(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != original {
		t.Fatalf("Undo() restored %q, want %q", data, original)
	}
	if _, err := os.Stat(restorePoint); err != nil {
		t.Fatalf("pre-undo backup missing: %v", err)
	}
}

func TestParseProtocols(t *testing.T) {
	got, err := ParseProtocols("smb,ldap,winrm")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"smb", "ldap", "winrm"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("ParseProtocols() = %#v, want %#v", got, want)
	}
}

func TestParseProtocolsAll(t *testing.T) {
	got, err := ParseProtocols("all")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(SupportedProtocols) {
		t.Fatalf("len(ParseProtocols(all)) = %d, want %d", len(got), len(SupportedProtocols))
	}
}

func TestDiscoverRunsProtocolsConcurrently(t *testing.T) {
	started := time.Now()
	entries, notes := discoverWithRunner("10.10.10.0/24", []string{"smb", "ldap", "winrm"}, func(protocol, target string) (string, error) {
		time.Sleep(100 * time.Millisecond)
		return "10.10.10.10 dc01.corp.local\n", nil
	})
	elapsed := time.Since(started)
	if elapsed >= 250*time.Millisecond {
		t.Fatalf("discoverWithRunner() took %s, want concurrent execution", elapsed)
	}
	if len(entries) != 1 || len(notes) != 3 {
		t.Fatalf("discoverWithRunner() entries=%#v notes=%#v", entries, notes)
	}
}

func TestRunNXCWithTimeoutRejectsNonPositiveTimeout(t *testing.T) {
	_, err := runNXCWithTimeout("smb", "10.10.10.0/24", 0)
	if err == nil || !strings.Contains(err.Error(), "timeout must be positive") {
		t.Fatalf("runNXCWithTimeout() error = %v, want timeout validation error", err)
	}
}

func TestValidateBootstrapCIDRRejectsNetworkAddress(t *testing.T) {
	err := validateBootstrapCIDR("192.168.56.0/24")
	if err == nil || !strings.Contains(err.Error(), "usable host address") {
		t.Fatalf("validateBootstrapCIDR() error = %v, want usable host address error", err)
	}
}

func TestValidateBootstrapCIDRRejectsBroadcastAddress(t *testing.T) {
	err := validateBootstrapCIDR("192.168.56.255/24")
	if err == nil || !strings.Contains(err.Error(), "usable host address") {
		t.Fatalf("validateBootstrapCIDR() error = %v, want usable host address error", err)
	}
}

func TestValidateBootstrapCIDRAcceptsHostAddress(t *testing.T) {
	if err := validateBootstrapCIDR("192.168.56.100/24"); err != nil {
		t.Fatalf("validateBootstrapCIDR() error = %v", err)
	}
}

func TestDetectLabCIDRUsesSinglePrivateNonDefaultInterface(t *testing.T) {
	got, err := DetectLabCIDR([]InterfaceNetwork{
		{Name: "eth0", CIDR: "192.168.49.131/24"},
		{Name: "eth1", CIDR: "192.168.56.100/24"},
	}, "eth0")
	if err != nil {
		t.Fatal(err)
	}
	if got != "192.168.56.0/24" {
		t.Fatalf("DetectLabCIDR() = %q, want %q", got, "192.168.56.0/24")
	}
}

func TestDetectLabCIDRRejectsAmbiguousPrivateInterfaces(t *testing.T) {
	_, err := DetectLabCIDR([]InterfaceNetwork{
		{Name: "eth0", CIDR: "192.168.49.131/24"},
		{Name: "eth1", CIDR: "192.168.56.100/24"},
		{Name: "eth2", CIDR: "10.10.10.100/24"},
	}, "eth0")
	if err == nil || !strings.Contains(err.Error(), "multiple lab subnets") {
		t.Fatalf("DetectLabCIDR() error = %v, want multiple lab subnets error", err)
	}
}

func TestDetectLabCIDRIgnoresLinkLocalAndLoopback(t *testing.T) {
	_, err := DetectLabCIDR([]InterfaceNetwork{
		{Name: "lo", CIDR: "127.0.0.1/8"},
		{Name: "eth0", CIDR: "192.168.49.131/24"},
		{Name: "eth1", CIDR: "169.254.12.34/16"},
	}, "eth0")
	if err == nil || !strings.Contains(err.Error(), "no lab subnet") {
		t.Fatalf("DetectLabCIDR() error = %v, want no lab subnet error", err)
	}
}

func TestDetectBootstrapInterfaceUsesSingleUnusedEthernet(t *testing.T) {
	got, err := DetectBootstrapInterface([]InterfaceState{
		{Name: "lo", Flags: net.FlagLoopback | net.FlagUp},
		{Name: "eth0", Flags: net.FlagUp, IPv4CIDRs: []string{"192.168.49.131/24"}},
		{Name: "eth1", Flags: net.FlagUp},
	}, "eth0", "")
	if err != nil {
		t.Fatal(err)
	}
	if got != "eth1" {
		t.Fatalf("DetectBootstrapInterface() = %q, want %q", got, "eth1")
	}
}

func TestDetectBootstrapInterfaceRejectsAmbiguousUnusedEthernet(t *testing.T) {
	_, err := DetectBootstrapInterface([]InterfaceState{
		{Name: "eth0", Flags: net.FlagUp, IPv4CIDRs: []string{"192.168.49.131/24"}},
		{Name: "eth1", Flags: net.FlagUp},
		{Name: "eth2", Flags: net.FlagUp},
	}, "eth0", "")
	if err == nil || !strings.Contains(err.Error(), "multiple candidate interfaces") {
		t.Fatalf("DetectBootstrapInterface() error = %v, want multiple candidate interfaces error", err)
	}
}

func TestDetectBootstrapInterfaceHonorsExplicitInterface(t *testing.T) {
	got, err := DetectBootstrapInterface([]InterfaceState{
		{Name: "eth0", Flags: net.FlagUp, IPv4CIDRs: []string{"192.168.49.131/24"}},
		{Name: "eth1", Flags: net.FlagUp},
		{Name: "eth2", Flags: net.FlagUp},
	}, "eth0", "eth2")
	if err != nil {
		t.Fatal(err)
	}
	if got != "eth2" {
		t.Fatalf("DetectBootstrapInterface() = %q, want %q", got, "eth2")
	}
}
