package hostsync

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type Entry struct {
	IP       string
	Hostname string
	Domain   string
	Source   string
}

func (e Entry) Names() []string {
	host := normalizeName(e.Hostname)
	domain := normalizeName(e.Domain)
	if host == "" || net.ParseIP(host) != nil {
		return nil
	}
	short := strings.Split(host, ".")[0]
	fqdn := host
	if !strings.Contains(host, ".") && domain != "" {
		fqdn = host + "." + domain
	}
	names := []string{fqdn}
	if short != fqdn {
		names = append(names, short)
	}
	return unique(names)
}

type Options struct {
	HostsPath string
	DryRun    bool
	Backup    bool
	Replace   bool
	Output    io.Writer
}

func BaselinePath(hostsPath string) string {
	return hostsPath + ".hostupdater.original"
}

var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;]*m`)
var ipPattern = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
var hostPattern = regexp.MustCompile(`(?i)\b(?:hostname|name):\s*([a-z0-9_.-]+)`)
var domainPattern = regexp.MustCompile(`(?i)\bdomain:\s*([a-z0-9_.-]+)`)

var SupportedProtocols = []string{"smb", "winrm", "mssql", "ldap", "ftp", "ssh", "rdp", "wmi", "vnc"}

const nxcTimeout = 45 * time.Second

func RunNXC(protocol, target string) (string, error) {
	return runNXCWithTimeout(protocol, target, nxcTimeout)
}

func runNXCWithTimeout(protocol, target string, timeout time.Duration) (string, error) {
	if !IsSupportedProtocol(protocol) {
		return "", fmt.Errorf("unsupported protocol %q", protocol)
	}
	if target == "" {
		return "", errors.New("target is required")
	}
	if timeout <= 0 {
		return "", errors.New("timeout must be positive")
	}
	path, err := exec.LookPath("nxc")
	if err != nil {
		return "", errors.New("nxc was not found in PATH; install NetExec or use parse mode with saved output")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := exec.CommandContext(ctx, path, protocol, target, "--generate-hosts-file", "/dev/stdout")
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return stdout.String(), fmt.Errorf("nxc %s timed out after %s", protocol, timeout)
		}
		return stdout.String(), fmt.Errorf("nxc %s failed: %w: %s", protocol, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

func Discover(target string, protocols []string) ([]Entry, []string) {
	return discoverWithRunner(target, protocols, RunNXC)
}

func discoverWithRunner(target string, protocols []string, runner func(string, string) (string, error)) ([]Entry, []string) {
	type result struct {
		entries []Entry
		note    string
	}
	results := make([]result, len(protocols))
	var wait sync.WaitGroup
	for index, protocol := range protocols {
		wait.Add(1)
		go func(index int, protocol string) {
			defer wait.Done()
			output, err := runner(protocol, target)
			entries := Parse(output, protocol)
			if err != nil {
				results[index].note = strings.ToUpper(protocol) + " discovery unavailable: " + err.Error()
				return
			}
			results[index] = result{
				entries: entries,
				note:    fmt.Sprintf("%s discovery returned %d valid mapping(s).", strings.ToUpper(protocol), len(entries)),
			}
		}(index, protocol)
	}
	wait.Wait()

	var notes []string
	var groups [][]Entry
	for _, result := range results {
		notes = append(notes, result.note)
		if len(result.entries) > 0 {
			groups = append(groups, result.entries)
		}
	}
	return MergeEntries(groups...), notes
}

func IsSupportedProtocol(protocol string) bool {
	for _, item := range SupportedProtocols {
		if item == strings.ToLower(strings.TrimSpace(protocol)) {
			return true
		}
	}
	return false
}

func ParseProtocols(value string) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		return []string{"smb"}, nil
	}
	if strings.EqualFold(value, "all") {
		return append([]string(nil), SupportedProtocols...), nil
	}
	seen := make(map[string]bool)
	var protocols []string
	for _, raw := range strings.Split(value, ",") {
		protocol := strings.ToLower(strings.TrimSpace(raw))
		if !IsSupportedProtocol(protocol) {
			return nil, fmt.Errorf("unsupported protocol %q", protocol)
		}
		if !seen[protocol] {
			protocols = append(protocols, protocol)
			seen[protocol] = true
		}
	}
	return protocols, nil
}

func Parse(output, source string) []Entry {
	output = ansiPattern.ReplaceAllString(output, "")
	var entries []Entry
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if entry, ok := parseHostsLine(line, source); ok {
			entries = append(entries, entry)
			continue
		}
		ip := ipPattern.FindString(line)
		if net.ParseIP(ip) == nil {
			continue
		}
		host := firstGroup(hostPattern, line)
		domain := firstGroup(domainPattern, line)
		if host == "" {
			fields := strings.Fields(line)
			host = guessHostname(fields, ip)
		}
		entry := Entry{IP: ip, Hostname: host, Domain: domain, Source: source}
		if len(entry.Names()) > 0 {
			entries = append(entries, entry)
		}
	}
	return MergeEntries(entries)
}

func MergeEntries(groups ...[]Entry) []Entry {
	byIP := make(map[string]Entry)
	for _, entries := range groups {
		for _, entry := range entries {
			if net.ParseIP(entry.IP) == nil || len(entry.Names()) == 0 {
				continue
			}
			current, exists := byIP[entry.IP]
			if !exists || score(entry) > score(current) {
				byIP[entry.IP] = entry
			}
		}
	}
	result := make([]Entry, 0, len(byIP))
	for _, entry := range byIP {
		result = append(result, entry)
	}
	sort.Slice(result, func(i, j int) bool {
		return bytes.Compare(net.ParseIP(result[i].IP), net.ParseIP(result[j].IP)) < 0
	})
	return result
}

func RenderManaged(entries []Entry) string {
	var builder strings.Builder
	builder.WriteString("# BEGIN HOSTUPDATER MANAGED BLOCK\n")
	for _, entry := range entries {
		names := entry.Names()
		if len(names) == 0 {
			continue
		}
		fmt.Fprintf(&builder, "%-15s %s # source=%s\n", entry.IP, strings.Join(names, " "), entry.Source)
	}
	builder.WriteString("# END HOSTUPDATER MANAGED BLOCK\n")
	return builder.String()
}

func UpdateHosts(entries []Entry, options Options) (string, error) {
	if options.Output == nil {
		options.Output = io.Discard
	}
	if options.HostsPath == "" {
		options.HostsPath = "/etc/hosts"
	}
	current, err := os.ReadFile(options.HostsPath)
	if err != nil {
		return "", err
	}
	next := replaceManagedBlock(string(current), RenderManaged(entries))
	if options.DryRun {
		return next, nil
	}
	if options.Backup {
		baseline := BaselinePath(options.HostsPath)
		if _, err := os.Stat(baseline); os.IsNotExist(err) {
			if err := os.WriteFile(baseline, current, 0o600); err != nil {
				return "", fmt.Errorf("write baseline backup: %w", err)
			}
			fmt.Fprintln(options.Output, "  [+] Baseline saved:", baseline)
		}
		backup := options.HostsPath + ".bak." + time.Now().Format("20060102_150405")
		if err := os.WriteFile(backup, current, 0o644); err != nil {
			return "", fmt.Errorf("write backup: %w", err)
		}
		fmt.Fprintln(options.Output, "  [+] Snapshot saved:", backup)
	}
	info, err := os.Stat(options.HostsPath)
	if err != nil {
		return "", err
	}
	temp, err := os.CreateTemp(filepath.Dir(options.HostsPath), ".hostupdater-*")
	if err != nil {
		return "", err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if _, err := temp.WriteString(next); err != nil {
		_ = temp.Close()
		return "", err
	}
	if err := temp.Chmod(info.Mode().Perm()); err != nil {
		_ = temp.Close()
		return "", err
	}
	if err := temp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tempPath, options.HostsPath); err != nil {
		return "", fmt.Errorf("replace hosts file: %w", err)
	}
	return next, nil
}

func Undo(hostsPath string, output io.Writer) (string, string, error) {
	if hostsPath == "" {
		hostsPath = "/etc/hosts"
	}
	if output == nil {
		output = io.Discard
	}
	baseline := BaselinePath(hostsPath)
	original, err := os.ReadFile(baseline)
	if err != nil {
		return "", "", fmt.Errorf("read baseline backup %s: %w", baseline, err)
	}
	current, err := os.ReadFile(hostsPath)
	if err != nil {
		return "", "", fmt.Errorf("read current hosts file: %w", err)
	}
	restorePoint := hostsPath + ".before-undo." + time.Now().Format("20060102_150405")
	if err := os.WriteFile(restorePoint, current, 0o600); err != nil {
		return "", "", fmt.Errorf("write pre-undo backup: %w", err)
	}
	info, err := os.Stat(hostsPath)
	if err != nil {
		return "", "", err
	}
	temp, err := os.CreateTemp(filepath.Dir(hostsPath), ".hostupdater-undo-*")
	if err != nil {
		return "", "", err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if _, err := temp.Write(original); err != nil {
		_ = temp.Close()
		return "", "", err
	}
	if err := temp.Chmod(info.Mode().Perm()); err != nil {
		_ = temp.Close()
		return "", "", err
	}
	if err := temp.Close(); err != nil {
		return "", "", err
	}
	if err := os.Rename(tempPath, hostsPath); err != nil {
		return "", "", fmt.Errorf("restore hosts file: %w", err)
	}
	fmt.Fprintln(output, "  [+] Restored:", baseline)
	fmt.Fprintln(output, "  [+] Pre-undo snapshot:", restorePoint)
	return baseline, restorePoint, nil
}

func parseHostsLine(line, source string) (Entry, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 || net.ParseIP(fields[0]) == nil {
		return Entry{}, false
	}
	host := normalizeName(fields[1])
	if host == "" || net.ParseIP(host) != nil {
		return Entry{}, false
	}
	entry := Entry{IP: fields[0], Hostname: host, Source: source}
	parts := strings.Split(host, ".")
	if len(parts) > 1 {
		entry.Domain = strings.Join(parts[1:], ".")
	}
	return entry, true
}

func replaceManagedBlock(current, managed string) string {
	for _, markers := range [][2]string{
		{"# BEGIN HOSTUPDATER MANAGED BLOCK", "# END HOSTUPDATER MANAGED BLOCK"},
		{"# BEGIN NXC-HOSTSYNC MANAGED BLOCK", "# END NXC-HOSTSYNC MANAGED BLOCK"},
	} {
		start := strings.Index(current, markers[0])
		finish := strings.Index(current, markers[1])
		if start >= 0 && finish >= start {
			finish += len(markers[1])
			current = strings.TrimRight(current[:start]+current[finish:], "\r\n")
		}
	}
	return strings.TrimRight(current, "\r\n") + "\n\n" + managed
}

func score(entry Entry) int {
	score := 0
	if entry.Source == "ldap" {
		score += 10
	}
	if entry.Domain != "" {
		score += 5
	}
	if strings.Contains(entry.Hostname, ".") {
		score += 2
	}
	return score
}

func normalizeName(value string) string {
	return strings.Trim(strings.ToLower(strings.TrimSpace(value)), "[](),;")
}

func firstGroup(pattern *regexp.Regexp, value string) string {
	matches := pattern.FindStringSubmatch(value)
	if len(matches) > 1 {
		return normalizeName(matches[1])
	}
	return ""
}

func guessHostname(fields []string, ip string) string {
	for _, field := range fields {
		field = normalizeName(field)
		if field == "" || field == ip || net.ParseIP(field) != nil || strings.Contains(field, ":") || strings.Contains(field, "=") {
			continue
		}
		if strings.Contains(field, ".") || strings.IndexFunc(field, func(r rune) bool {
			return r >= 'a' && r <= 'z'
		}) >= 0 {
			return field
		}
	}
	return ""
}

func unique(values []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, value := range values {
		if value != "" && !seen[value] {
			result = append(result, value)
			seen[value] = true
		}
	}
	return result
}
