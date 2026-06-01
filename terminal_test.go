package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestPrintBannerWithColor(t *testing.T) {
	var output bytes.Buffer
	printBanner(&output, palette{enabled: true})
	got := output.String()
	if !strings.Contains(got, "hostUpdater") || !strings.Contains(got, "\x1b[94m") {
		t.Fatalf("printBanner() output = %q", got)
	}
	if !strings.Contains(got, "nxc /etc/hosts automatic sync | by: \x1b[1m\x1b[91mshanksf\x1b[0m\x1b[0m inspired by \x1b[1m\x1b[91meMVee\x1b[0m\x1b[0m") {
		t.Fatalf("printBanner() subtitle = %q", got)
	}
}

func TestPrintBannerWithoutColorKeepsSubtitleReadable(t *testing.T) {
	var output bytes.Buffer
	printBanner(&output, palette{})
	if !strings.Contains(output.String(), "nxc /etc/hosts automatic sync | by: shanksf inspired by eMVee") {
		t.Fatalf("printBanner() plain subtitle = %q", output.String())
	}
}

func TestPrintUsageWithColorStylesSectionsCommandsAndOptions(t *testing.T) {
	var output bytes.Buffer
	printUsage(&output, palette{enabled: true})
	got := output.String()
	for _, expected := range []string{
		"\x1b[1m\x1b[96mUSAGE\x1b[0m\x1b[0m",
		"\x1b[1m\x1b[92mscan     \x1b[0m\x1b[0m",
		"\x1b[1m\x1b[93m--quick               \x1b[0m\x1b[0m",
		"\x1b[96msudo hostupdater scan\x1b[0m",
	} {
		if !strings.Contains(got, expected) {
			t.Fatalf("printUsage() omitted style %q:\n%s", expected, got)
		}
	}
}

func TestColorManagedBlock(t *testing.T) {
	got := colorManagedBlock("# BEGIN HOSTUPDATER MANAGED BLOCK\n10.10.10.10 dc01.local\n# END HOSTUPDATER MANAGED BLOCK\n", palette{enabled: true})
	if !strings.Contains(got, "\x1b[94m") || !strings.Contains(got, "\x1b[92m") {
		t.Fatalf("colorManagedBlock() omitted colors: %q", got)
	}
}
