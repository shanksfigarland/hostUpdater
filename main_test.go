package main

import (
	"strings"
	"testing"
	"time"
)

func TestUsageKeepsTopLevelHelpCompact(t *testing.T) {
	var output strings.Builder
	usageTo(&output)
	got := output.String()
	for _, expected := range []string{
		"sudo hostupdater scan",
		"sudo hostupdater scan -t CIDR",
		"sudo hostupdater scan --dry-run",
		"scan      Discover hosts and update /etc/hosts",
		"--quick",
	} {
		if !strings.Contains(got, expected) {
			t.Fatalf("usageTo() omitted %q:\n%s", expected, got)
		}
	}
	for _, unwanted := range []string{
		"PARSE MODE",
		"PIPE EXAMPLE",
		"PROTOCOL EXAMPLES",
		"SAFE UPDATE BEHAVIOR",
		"--bootstrap-cidr",
	} {
		if strings.Contains(got, unwanted) {
			t.Fatalf("usageTo() included advanced detail %q:\n%s", unwanted, got)
		}
	}
}

func TestScanProtocolsDefaultsToAllSupportedProtocols(t *testing.T) {
	got, err := scanProtocols(false, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "smb,winrm,mssql,ldap,ftp,ssh,rdp,wmi,vnc" {
		t.Fatalf("scanProtocols() = %#v", got)
	}
}

func TestScanProtocolsQuickUsesSMBOnly(t *testing.T) {
	got, err := scanProtocols(true, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "smb" {
		t.Fatalf("scanProtocols(quick) = %#v, want smb", got)
	}
}

func TestAvailableProtocolsReturnsSuccessfulDiscoveryProtocols(t *testing.T) {
	got := availableProtocols([]string{
		"SMB discovery returned 4 valid mapping(s).",
		"LDAP discovery returned 2 valid mapping(s).",
		"WINRM discovery unavailable: connection refused",
	})
	if strings.Join(got, ",") != "SMB,LDAP" {
		t.Fatalf("availableProtocols() = %#v, want SMB,LDAP", got)
	}
}

func TestFormatScanDuration(t *testing.T) {
	if got := formatScanDuration(1250 * time.Millisecond); got != "1.3s" {
		t.Fatalf("formatScanDuration() = %q, want 1.3s", got)
	}
}

func TestPadVisible(t *testing.T) {
	if got := padVisible("LDAP", 6); got != "LDAP  " {
		t.Fatalf("padVisible() = %q", got)
	}
	if got := padVisible("dc01.corp.local", 8); got != "dc01.co~" {
		t.Fatalf("padVisible() truncated value = %q", got)
	}
}

func TestConfirmApplyAcceptsYes(t *testing.T) {
	var output strings.Builder
	if !confirmApply(strings.NewReader("yes\n"), &output, palette{}) {
		t.Fatal("confirmApply() = false, want true")
	}
	if !strings.Contains(output.String(), "Add these hosts to /etc/hosts?") {
		t.Fatalf("confirmApply() prompt = %q", output.String())
	}
}

func TestConfirmApplyDefaultsToNo(t *testing.T) {
	if confirmApply(strings.NewReader("\n"), &strings.Builder{}, palette{}) {
		t.Fatal("confirmApply() = true, want false")
	}
}

func TestConfirmBootstrapAcceptsYes(t *testing.T) {
	var output strings.Builder
	if !confirmBootstrap(strings.NewReader("y\n"), &output, "eth1", "192.168.56.100/24", palette{}) {
		t.Fatal("confirmBootstrap() = false, want true")
	}
	if !strings.Contains(output.String(), "Configure eth1 temporarily as 192.168.56.100/24?") {
		t.Fatalf("confirmBootstrap() prompt = %q", output.String())
	}
}

func TestPromptBootstrapCIDRReturnsEnteredValue(t *testing.T) {
	var output strings.Builder
	got := promptBootstrapCIDR(strings.NewReader("10.10.10.100/24\n"), &output, palette{})
	if got != "10.10.10.100/24" {
		t.Fatalf("promptBootstrapCIDR() = %q", got)
	}
	if !strings.Contains(output.String(), "Enter a temporary attacker CIDR") {
		t.Fatalf("promptBootstrapCIDR() prompt = %q", output.String())
	}
	if !strings.HasPrefix(output.String(), "\n  [?]") || !strings.HasSuffix(output.String(), "\n\n") {
		t.Fatalf("promptBootstrapCIDR() spacing = %q, want blank lines before and after prompt", output.String())
	}
}

func TestPromptTargetCIDRAcceptsDetectedSubnet(t *testing.T) {
	var output strings.Builder
	got := promptTargetCIDR(strings.NewReader("\n"), &output, "192.168.56.0/24", palette{})
	if got != "192.168.56.0/24" {
		t.Fatalf("promptTargetCIDR() = %q", got)
	}
	if !strings.Contains(output.String(), "Use detected subnet 192.168.56.0/24?") {
		t.Fatalf("promptTargetCIDR() prompt = %q", output.String())
	}
	if !strings.HasPrefix(output.String(), "\n  [?]") || !strings.HasSuffix(output.String(), "\n\n") {
		t.Fatalf("promptTargetCIDR() spacing = %q, want blank lines before and after prompt", output.String())
	}
}

func TestPromptTargetCIDRAllowsOverride(t *testing.T) {
	got := promptTargetCIDR(strings.NewReader("10.10.10.0/24\n"), &strings.Builder{}, "192.168.56.0/24", palette{})
	if got != "10.10.10.0/24" {
		t.Fatalf("promptTargetCIDR() = %q", got)
	}
}
