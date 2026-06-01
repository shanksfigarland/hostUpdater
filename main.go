package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/shanksf/hostUpdater/internal/hostsync"
)

const version = "0.2.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}
	switch os.Args[1] {
	case "scan":
		scan(os.Args[2:])
	case "parse":
		parse(os.Args[2:])
	case "undo":
		undo(os.Args[2:])
	case "version", "--version":
		fmt.Println("hostUpdater", version)
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "error: unknown command %q\n\n", os.Args[1])
		usage()
	}
}

func undo(args []string) {
	flags := flag.NewFlagSet("undo", flag.ExitOnError)
	flags.SetOutput(os.Stdout)
	flags.Usage = func() { undoUsage(os.Stdout) }
	hostsPath := flags.String("hosts", "/etc/hosts", "hosts file path")
	color := flags.String("color", "auto", "color mode: auto, always, or never")
	_ = flags.Parse(args)
	colors := detectPalette(*color, os.Stdout)
	printBanner(os.Stdout, colors)
	fmt.Printf("  %s Restoring baseline for %s\n", colors.statusYellow("[~]"), colors.bold(colors.cyan(*hostsPath)))
	baseline, restorePoint, err := hostsync.Undo(*hostsPath, os.Stdout)
	fatalIf(err)
	fmt.Printf("\n  %s %s\n", colors.statusGreen("[+]"), colors.bold(colors.green("Restored original hosts file.")))
	fmt.Printf("  %s %s %s\n", colors.statusBlue("[*]"), colors.bold("Baseline:"), colors.cyan(baseline))
	fmt.Printf("  %s %s %s\n", colors.statusBlue("[*]"), colors.bold("Current state backup:"), colors.cyan(restorePoint))
}

func scan(args []string) {
	flags := flag.NewFlagSet("scan", flag.ExitOnError)
	flags.SetOutput(os.Stdout)
	flags.Usage = func() { scanUsage(os.Stdout) }
	target := ""
	flags.StringVar(&target, "target", "", "network target; auto-detected when omitted")
	flags.StringVar(&target, "t", "", "network target; auto-detected when omitted")
	interfaceName := flags.String("interface", "", "unused lab interface to configure when auto-detection needs bootstrap")
	bootstrapCIDR := flags.String("bootstrap-cidr", "", "temporary lab address used for interface bootstrap")
	quickMode := flags.Bool("quick", false, "scan SMB only")
	protocolsValue := flags.String("protocols", "", "comma-separated nxc protocols or all")
	protocolValue := flags.String("protocol", "", "single nxc protocol shorthand")
	hostsPath := flags.String("hosts", "/etc/hosts", "hosts file path")
	dryRun := flags.Bool("dry-run", false, "print proposed hosts file without writing")
	noBackup := flags.Bool("no-backup", false, "skip timestamped backup")
	yes := flags.Bool("yes", false, "write discovered hosts without confirmation")
	color := flags.String("color", "auto", "color mode: auto, always, or never")
	quiet := flags.Bool("quiet", false, "suppress discovery details")
	verbose := false
	flags.BoolVar(&verbose, "verbose", false, "show detailed NetExec discovery notes")
	flags.BoolVar(&verbose, "v", false, "show detailed NetExec discovery notes")
	_ = flags.Parse(args)
	colors := detectPalette(*color, os.Stdout)
	if target == "" {
		var err error
		target, err = hostsync.AutoDetectLabCIDR()
		if err != nil {
			candidate, candidateErr := hostsync.AutoDetectBootstrapInterface(*interfaceName)
			fatalIf(candidateErr)
			if *bootstrapCIDR == "" {
				*bootstrapCIDR = promptBootstrapCIDR(os.Stdin, os.Stdout, colors)
				if *bootstrapCIDR == "" {
					fmt.Println("  [~] Interface was not configured.")
					return
				}
			}
			if !confirmBootstrap(os.Stdin, os.Stdout, candidate, *bootstrapCIDR, colors) {
				fmt.Println("  [~] Interface was not configured.")
				return
			}
			fatalIf(hostsync.ConfigureTemporaryAddress(candidate, *bootstrapCIDR))
			fmt.Printf("  %s\n", colors.bold(colors.green(fmt.Sprintf("[+] Configured %s as %s for this session.", candidate, *bootstrapCIDR))))
			target, err = hostsync.AutoDetectLabCIDR()
		}
		fatalIf(err)
		target = promptTargetCIDR(os.Stdin, os.Stdout, target, colors)
		if target == "" {
			fmt.Println("  [~] No target subnet selected.")
			return
		}
	}
	protocols, err := scanProtocols(*quickMode, *protocolValue, *protocolsValue)
	fatalIf(err)
	started := time.Now()
	entries, notes := hostsync.Discover(target, protocols)
	elapsed := time.Since(started)
	if !*quiet {
		printHeader(entries, notes, protocols, colors, verbose, elapsed)
	}
	if len(entries) == 0 {
		fatal("no valid hostname mappings discovered")
	}
	if !*dryRun && !*yes && !confirmApply(os.Stdin, os.Stdout, colors) {
		fmt.Println("  [~] No changes written.")
		return
	}
	apply(entries, *hostsPath, *dryRun, !*noBackup, colors)
}

func promptTargetCIDR(reader io.Reader, writer io.Writer, detectedCIDR string, colors palette) string {
	fmt.Fprintf(writer, "\n  %s Use detected subnet %s? Press Enter to accept or type another CIDR: ", colors.statusYellow("[?]"), colors.magenta(detectedCIDR))
	line, err := bufio.NewReader(reader).ReadString('\n')
	fmt.Fprint(writer, "\n\n")
	if err != nil && err != io.EOF {
		return ""
	}
	value := strings.TrimSpace(line)
	if value == "" {
		return detectedCIDR
	}
	return value
}

func promptBootstrapCIDR(reader io.Reader, writer io.Writer, colors palette) string {
	fmt.Fprintf(writer, "\n  %s Enter a temporary attacker CIDR, for example %s: ", colors.statusYellow("[?]"), colors.magenta("10.10.10.100/24"))
	line, err := bufio.NewReader(reader).ReadString('\n')
	fmt.Fprint(writer, "\n\n")
	if err != nil && err != io.EOF {
		return ""
	}
	return strings.TrimSpace(line)
}

func confirmBootstrap(reader io.Reader, writer io.Writer, interfaceName, cidr string, colors palette) bool {
	fmt.Fprintf(writer, "  %s Configure %s temporarily as %s? %s ", colors.statusYellow("[?]"), colors.cyan(interfaceName), colors.magenta(cidr), colors.bold("[y/N]:"))
	line, err := bufio.NewReader(reader).ReadString('\n')
	if err != nil && err != io.EOF {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}

func confirmApply(reader io.Reader, writer io.Writer, colors palette) bool {
	fmt.Fprintf(writer, "  %s Add these hosts to %s? %s ", colors.statusYellow("[?]"), colors.cyan("/etc/hosts"), colors.bold("[y/N]:"))
	line, err := bufio.NewReader(reader).ReadString('\n')
	if err != nil && err != io.EOF {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}

func parse(args []string) {
	flags := flag.NewFlagSet("parse", flag.ExitOnError)
	flags.SetOutput(os.Stdout)
	flags.Usage = func() { parseUsage(os.Stdout) }
	input := flags.String("input", "-", "saved nxc output path or - for stdin")
	source := flags.String("source", "ldap", "source format: ldap or smb")
	hostsPath := flags.String("hosts", "/etc/hosts", "hosts file path")
	dryRun := flags.Bool("dry-run", false, "print proposed hosts file without writing")
	noBackup := flags.Bool("no-backup", false, "skip timestamped backup")
	color := flags.String("color", "auto", "color mode: auto, always, or never")
	quiet := flags.Bool("quiet", false, "suppress discovery details")
	verbose := false
	flags.BoolVar(&verbose, "verbose", false, "show detailed parse notes")
	flags.BoolVar(&verbose, "v", false, "show detailed parse notes")
	_ = flags.Parse(args)
	if *source != "ldap" && *source != "smb" {
		fatal("source must be ldap or smb")
	}
	payload, err := readInput(*input)
	fatalIf(err)
	entries := hostsync.Parse(string(payload), *source)
	colors := detectPalette(*color, os.Stdout)
	if !*quiet {
		printHeader(entries, nil, []string{*source}, colors, verbose, 0)
	}
	apply(entries, *hostsPath, *dryRun, !*noBackup, colors)
}

func apply(entries []hostsync.Entry, hostsPath string, dryRun, backup bool, colors palette) {
	if len(entries) == 0 {
		fatal("no valid hostname mappings discovered")
	}
	next, err := hostsync.UpdateHosts(entries, hostsync.Options{
		HostsPath: hostsPath,
		DryRun:    dryRun,
		Backup:    backup,
		Output:    os.Stdout,
	})
	fatalIf(err)
	if dryRun {
		fmt.Printf("\n  %s %s\n", colors.statusYellow("[~]"), colors.bold(colors.yellow("DRY RUN // PROPOSED HOSTS FILE")))
		fmt.Println("  " + colors.dim(strings.Repeat("-", 64)))
		fmt.Print(colorManagedBlock(next, colors))
		fmt.Println("  " + colors.dim(strings.Repeat("-", 64)))
		return
	}
	fmt.Printf("\n  %s %s %s %s\n", colors.statusGreen("[+]"), colors.bold(colors.green("UPDATED")), colors.bold(colors.cyan(hostsPath)), colors.bold(colors.green(fmt.Sprintf("(%d managed entries)", len(entries)))))
}

func printHeader(entries []hostsync.Entry, notes, protocols []string, colors palette, verbose bool, elapsed time.Duration) {
	printBanner(os.Stdout, colors)
	fmt.Printf("  %s %s %s\n", colors.statusBlue("[*]"), colors.bold("Protocols:"), colors.bold(colors.magenta(strings.Join(protocols, ", "))))
	available := availableProtocols(notes)
	if len(available) > 0 {
		fmt.Printf("  %s %s %s\n", colors.statusGreen("[+]"), colors.bold("Available:"), colors.bold(colors.green(strings.Join(available, ", "))))
	}
	fmt.Printf("  %s %s %s\n", colors.statusGreen("[+]"), colors.bold("Valid hosts:"), colors.bold(colors.green(fmt.Sprintf("%d", len(entries)))))
	if elapsed > 0 {
		fmt.Printf("  %s %s %s\n", colors.statusBlue("[*]"), colors.bold("Elapsed:"), colors.bold(colors.cyan(formatScanDuration(elapsed))))
	}
	if verbose {
		for _, note := range notes {
			fmt.Printf("  %s %s\n", colors.statusYellow("[~]"), colors.dim(note))
		}
	}
	fmt.Println()
	fmt.Printf("  %s  %s  %s\n",
		colors.bold(padVisible("IP ADDRESS", 15)),
		colors.bold(padVisible("SOURCE", 6)),
		colors.bold("HOSTNAMES"))
	for _, entry := range entries {
		source := colors.bold(colors.blue(padVisible(strings.ToUpper(entry.Source), 6)))
		fmt.Printf("  %s  %s  %s\n",
			colors.cyan(padVisible(entry.IP, 15)),
			source,
			colors.bold(colors.green(strings.Join(entry.Names(), " "))))
	}
	fmt.Println()
}

func formatScanDuration(elapsed time.Duration) string {
	return fmt.Sprintf("%.1fs", elapsed.Seconds())
}

func availableProtocols(notes []string) []string {
	var available []string
	for _, note := range notes {
		protocol, _, ok := strings.Cut(note, " discovery returned ")
		if ok {
			available = append(available, protocol)
		}
	}
	return available
}

func padVisible(value string, width int) string {
	runes := []rune(value)
	if len(runes) > width {
		if width <= 1 {
			return string(runes[:width])
		}
		return string(runes[:width-1]) + "~"
	}
	return value + strings.Repeat(" ", width-len(runes))
}

func colorManagedBlock(value string, colors palette) string {
	var builder strings.Builder
	for _, line := range strings.SplitAfter(value, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "# BEGIN HOSTUPDATER"), strings.HasPrefix(trimmed, "# END HOSTUPDATER"):
			builder.WriteString(colors.blue(strings.TrimSuffix(line, "\n")))
			if strings.HasSuffix(line, "\n") {
				builder.WriteString("\n")
			}
		case trimmed != "" && !strings.HasPrefix(trimmed, "#"):
			builder.WriteString(colors.green(strings.TrimSuffix(line, "\n")))
			if strings.HasSuffix(line, "\n") {
				builder.WriteString("\n")
			}
		default:
			builder.WriteString(line)
		}
	}
	return builder.String()
}

func readInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func scanProtocols(quick bool, protocol, protocols string) ([]string, error) {
	if quick {
		if protocol != "" || protocols != "" {
			return nil, fmt.Errorf("--quick cannot be combined with --protocol or --protocols")
		}
		return []string{"smb"}, nil
	}
	if protocol != "" {
		if protocols != "" {
			return nil, fmt.Errorf("--protocol cannot be combined with --protocols")
		}
		return hostsync.ParseProtocols(protocol)
	}
	if protocols != "" {
		return hostsync.ParseProtocols(protocols)
	}
	return hostsync.ParseProtocols("all")
}

func usage() {
	usageTo(os.Stdout)
}

func usageTo(output io.Writer) {
	colors := detectPalette("auto", output)
	printBanner(output, colors)
	printUsage(output, colors)
}

func printUsage(output io.Writer, colors palette) {
	fmt.Fprintf(output, "  %s\n", colors.bold("Discover NetExec hosts and safely sync /etc/hosts."))
	fmt.Fprintln(output)
	fmt.Fprintf(output, "  %s\n", colors.bold(colors.cyan("USAGE")))
	fmt.Fprintf(output, "    %s\n", colors.cyan("sudo hostupdater scan"))
	fmt.Fprintf(output, "    %s\n", colors.cyan("sudo hostupdater scan -t CIDR"))
	fmt.Fprintf(output, "    %s\n", colors.cyan("sudo hostupdater scan --dry-run"))
	fmt.Fprintln(output)
	fmt.Fprintf(output, "  %s\n", colors.bold(colors.cyan("COMMANDS")))
	fmt.Fprintf(output, "    %s %s\n", colors.bold(colors.green(padVisible("scan", 9))), "Discover hosts and update /etc/hosts")
	fmt.Fprintf(output, "    %s %s\n", colors.bold(colors.green(padVisible("undo", 9))), "Restore the original hosts file")
	fmt.Fprintf(output, "    %s %s\n", colors.bold(colors.green(padVisible("parse", 9))), "Import saved NetExec output")
	fmt.Fprintf(output, "    %s %s\n", colors.bold(colors.green(padVisible("version", 9))), "Print version")
	fmt.Fprintln(output)
	fmt.Fprintf(output, "  %s\n", colors.bold(colors.cyan("COMMON OPTIONS")))
	fmt.Fprintf(output, "    %s %s\n", colors.bold(colors.yellow(padVisible("-t, --target CIDR", 22))), "Scan a specific subnet")
	fmt.Fprintf(output, "    %s %s\n", colors.bold(colors.yellow(padVisible("--quick", 22))), "Scan SMB only")
	fmt.Fprintf(output, "    %s %s\n", colors.bold(colors.yellow(padVisible("--dry-run", 22))), "Preview changes without writing")
	fmt.Fprintf(output, "    %s %s\n", colors.bold(colors.yellow(padVisible("-v, --verbose", 22))), "Show scan details")
	fmt.Fprintln(output)
	fmt.Fprintf(output, "  Run %s for advanced scan options.\n", colors.bold(colors.magenta("hostupdater scan --help")))
}

func scanUsage(output io.Writer) {
	fmt.Fprintln(output, "Usage: hostupdater scan [options]")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Scans all supported NetExec protocols concurrently by default.")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Options:")
	fmt.Fprintln(output, "  -t, --target CIDR     Override the auto-detected lab network")
	fmt.Fprintln(output, "  --quick               Scan SMB only")
	fmt.Fprintln(output, "  --protocol NAME       Scan one protocol")
	fmt.Fprintln(output, "  --protocols LIST      Scan comma-separated protocols or all")
	fmt.Fprintln(output, "  --interface NAME      Select an unused interface for bootstrap")
	fmt.Fprintln(output, "  --bootstrap-cidr CIDR Temporary address for interface bootstrap")
	fmt.Fprintln(output, "  --hosts PATH          Hosts file path, default /etc/hosts")
	fmt.Fprintln(output, "  --dry-run             Preview changes without writing")
	fmt.Fprintln(output, "  --yes                 Write without confirmation")
	fmt.Fprintln(output, "  --no-backup           Skip timestamped backup creation")
	fmt.Fprintln(output, "  --quiet               Suppress discovery details")
	fmt.Fprintln(output, "  -v, --verbose         Show NetExec discovery notes")
}

func parseUsage(output io.Writer) {
	fmt.Fprintln(output, "Usage: hostupdater parse --input PATH --source ldap|smb [options]")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Imports saved NetExec output or stdin without running NetExec.")
	fmt.Fprintln(output, "Use --input - to read from stdin.")
}

func undoUsage(output io.Writer) {
	fmt.Fprintln(output, "Usage: sudo hostupdater undo [--hosts PATH]")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Restores the baseline captured before the first hosts-file update.")
}

func fatalIf(err error) {
	if err != nil {
		fatal(err.Error())
	}
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, "error:", message)
	os.Exit(1)
}
