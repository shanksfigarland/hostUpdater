package hostsync

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
)

type InterfaceNetwork struct {
	Name string
	CIDR string
}

type InterfaceState struct {
	Name      string
	Flags     net.Flags
	IPv4CIDRs []string
}

func AutoDetectLabCIDR() (string, error) {
	defaultInterface, err := defaultRouteInterface("/proc/net/route")
	if err != nil {
		return "", err
	}
	networks, err := localInterfaceNetworks()
	if err != nil {
		return "", err
	}
	return DetectLabCIDR(networks, defaultInterface)
}

func AutoDetectBootstrapInterface(explicitInterface string) (string, error) {
	defaultInterface, _ := defaultRouteInterface("/proc/net/route")
	states, err := localInterfaceStates()
	if err != nil {
		return "", err
	}
	return DetectBootstrapInterface(states, defaultInterface, explicitInterface)
}

func DetectBootstrapInterface(states []InterfaceState, defaultInterface, explicitInterface string) (string, error) {
	if explicitInterface != "" {
		for _, state := range states {
			if state.Name == explicitInterface {
				return state.Name, nil
			}
		}
		return "", fmt.Errorf("interface %q not found", explicitInterface)
	}
	var candidates []string
	for _, state := range states {
		if state.Name == defaultInterface || state.Flags&net.FlagLoopback != 0 || state.Flags&net.FlagUp == 0 {
			continue
		}
		if len(state.IPv4CIDRs) == 0 || onlyLinkLocal(state.IPv4CIDRs) {
			candidates = append(candidates, state.Name)
		}
	}
	sort.Strings(candidates)
	switch len(candidates) {
	case 0:
		return "", errors.New("no unused Ethernet interface detected; use --interface NAME")
	case 1:
		return candidates[0], nil
	default:
		return "", fmt.Errorf("multiple candidate interfaces detected (%s); use --interface NAME", strings.Join(candidates, ", "))
	}
}

func ConfigureTemporaryAddress(interfaceName, cidr string) error {
	if interfaceName == "" {
		return errors.New("interface is required")
	}
	if err := validateBootstrapCIDR(cidr); err != nil {
		return err
	}
	for _, arguments := range [][]string{
		{"link", "set", interfaceName, "up"},
		{"addr", "add", cidr, "dev", interfaceName},
	} {
		command := exec.Command("ip", arguments...)
		output, err := command.CombinedOutput()
		if err != nil && !strings.Contains(string(output), "File exists") {
			return fmt.Errorf("ip %s failed: %w: %s", strings.Join(arguments, " "), err, strings.TrimSpace(string(output)))
		}
	}
	return nil
}

func validateBootstrapCIDR(value string) error {
	ip, network, err := net.ParseCIDR(value)
	if err != nil || ip.To4() == nil {
		return fmt.Errorf("invalid IPv4 bootstrap CIDR %q", value)
	}
	ip = ip.To4()
	networkIP := network.IP.To4()
	broadcast := make(net.IP, len(networkIP))
	for index := range networkIP {
		broadcast[index] = networkIP[index] | ^network.Mask[index]
	}
	if ip.Equal(networkIP) || ip.Equal(broadcast) {
		return fmt.Errorf("bootstrap CIDR %q must use a usable host address", value)
	}
	return nil
}

func DetectLabCIDR(networks []InterfaceNetwork, defaultInterface string) (string, error) {
	seen := make(map[string]bool)
	var candidates []string
	for _, network := range networks {
		if network.Name == defaultInterface {
			continue
		}
		ip, cidr, err := net.ParseCIDR(network.CIDR)
		if err != nil || ip == nil || cidr == nil || !ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		ones, bits := cidr.Mask.Size()
		if bits != 32 || ones == 32 {
			continue
		}
		value := cidr.String()
		if !seen[value] {
			candidates = append(candidates, value)
			seen[value] = true
		}
	}
	sort.Strings(candidates)
	switch len(candidates) {
	case 0:
		return "", errors.New("no lab subnet detected; use --target CIDR")
	case 1:
		return candidates[0], nil
	default:
		return "", fmt.Errorf("multiple lab subnets detected (%s); use --target CIDR", strings.Join(candidates, ", "))
	}
}

func localInterfaceNetworks() ([]InterfaceNetwork, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	var networks []InterfaceNetwork
	for _, networkInterface := range interfaces {
		if networkInterface.Flags&net.FlagUp == 0 {
			continue
		}
		addresses, err := networkInterface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("list addresses for %s: %w", networkInterface.Name, err)
		}
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err != nil || ip.To4() == nil {
				continue
			}
			networks = append(networks, InterfaceNetwork{Name: networkInterface.Name, CIDR: address.String()})
		}
	}
	return networks, nil
}

func localInterfaceStates() ([]InterfaceState, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	var states []InterfaceState
	for _, networkInterface := range interfaces {
		state := InterfaceState{Name: networkInterface.Name, Flags: networkInterface.Flags}
		addresses, err := networkInterface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("list addresses for %s: %w", networkInterface.Name, err)
		}
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err == nil && ip.To4() != nil {
				state.IPv4CIDRs = append(state.IPv4CIDRs, address.String())
			}
		}
		states = append(states, state)
	}
	return states, nil
}

func onlyLinkLocal(cidrs []string) bool {
	if len(cidrs) == 0 {
		return false
	}
	for _, cidr := range cidrs {
		ip, _, err := net.ParseCIDR(cidr)
		if err != nil || !ip.IsLinkLocalUnicast() {
			return false
		}
	}
	return true
}

func defaultRouteInterface(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("read default route: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return "", errors.New("read default route: empty route table")
	}
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[1] == "00000000" {
			return fields[0], nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("read default route: %w", err)
	}
	return "", errors.New("default route not found; use --target CIDR")
}
