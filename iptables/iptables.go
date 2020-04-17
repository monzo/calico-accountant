package iptables

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/golang/glog"
	"github.com/monzo/calico-accountant/watch"
	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
)

type ChainType int
type CountType int
type PolicyType int

const (
	ToWorkLoad ChainType = iota
	FromWorkLoad
	Drop CountType = iota
	Accept
	AcceptedDrop
	PolicyInbound PolicyType = iota
	PolicyOutbound
)

func chainTypeFromString(str string) ChainType {
	switch str {
	case "fw":
		return FromWorkLoad
	case "tw":
		return ToWorkLoad
	default:
		glog.Fatalf("Unsupported chain type: %s", str)
		// unreachable
		return 0
	}
}

func policyTypeFromString(str string) PolicyType {
	switch str {
	case "pi":
		return PolicyInbound
	case "po":
		return PolicyOutbound
	default:
		glog.Fatalf("Unsupported policy type: %s", str)
		// unreachable
		return 0
	}
}

func (pt PolicyType) String() string {
	switch pt {
	case PolicyInbound:
		return "inbound"
	case PolicyOutbound:
		return "outbound"
	default:
		glog.Fatalf("Unsupported policy type: %d", pt)
		return ""
	}
}

func (ct ChainType) String() string {
	switch ct {
	case ToWorkLoad:
		return "tw"
	case FromWorkLoad:
		return "fw"
	default:
		glog.Fatalf("Unsupported chain type: %d", ct)
		// unreachable
		return ""
	}
}

type Result struct {
	PodName      string
	PodNamespace string
	AppLabel     string
	PodIP        string
	ChainType    ChainType
	CountType    CountType
	PacketCount  int
	Target       string
}

type DropChain struct {
	PolicyType  PolicyType
	PacketCount int
}

func Scan(cw watch.CalicoWatcher) ([]*Result, error) {
	// first build a mapping from interface names to workload endpoints
	workloads := cw.ListWorkloadEndpoints()

	interfaceToWorkload := make(map[string]*apiv3.WorkloadEndpoint, len(workloads))
	for _, w := range workloads {
		interfaceToWorkload[w.Spec.InterfaceName] = w
	}

	return iptablesSave(interfaceToWorkload)
}

var (
	appendRegexp    = regexp.MustCompile(`^\[(\d+):\d+] -A cali-([tf]w)-(\S+).*-j (\S+)$`)
	dropPolicyRegex = regexp.MustCompile(`^\[(\d+):\d+] -A (cali-(p[io])-(\S+)).*-j DROP$`)
	dropSlice       = []byte("Drop if no policies passed packet")
	acceptSlice     = []byte("Return if policy accepted")
)

func iptablesSave(interfaceToWorkload map[string]*apiv3.WorkloadEndpoint) ([]*Result, error) {
	cmd := exec.Command("iptables-save", "-t", "filter", "-c")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		glog.Errorf("Failed to get iptables-save stdout pipe: %v", err)
		return nil, err
	}
	err = cmd.Start()
	if err != nil {
		// Failed even before we started, close the pipe.  (This would normally be done
		// by Wait().
		glog.Errorf("Failed to start iptables-save: %v", err)
		closeErr := stdout.Close()
		if closeErr != nil {
			glog.Errorf("Error closing iptables-save stdout after Start() failed: %v", err)
		}
		return nil, err
	}

	results, err := parseFrom(stdout, interfaceToWorkload)
	if err != nil {
		killErr := cmd.Process.Kill()
		if killErr != nil {
			glog.Errorf("Failed to kill iptables-save process: %v", killErr)
		}
		return nil, err
	}

	if err := cmd.Wait(); err != nil {
		glog.Errorf("iptables-save failed: %v", err)
		return nil, err
	}
	return results, nil
}

// parseFrom extracts useful packet counts from the output of iptables-save
// inspiration is taken from projectcalico/felix/iptables/table.go
func parseFrom(stdout io.Reader, interfaceToWorkload map[string]*apiv3.WorkloadEndpoint) ([]*Result, error) {
	// we expect at most 4 counts per network interface, drop and accept for ingress and egress
	results := make([]*Result, 0, 4*len(interfaceToWorkload))
	dropChains := map[string]DropChain{}

	// Create a buffer because we loop through the output twice.
	var buf bytes.Buffer
	tee := io.TeeReader(stdout, &buf)

	dropScanner := bufio.NewScanner(tee)
	// Parse the entire output to find policies that have DROP actions and store
	// the packet count so it can be used later.
	for dropScanner.Scan() {
		line := dropScanner.Bytes()
		dropCapture := dropPolicyRegex.FindSubmatch(line)
		if dropCapture != nil {
			glog.V(3).Infof("Found drop policy: %s, packet count: %s", string(dropCapture[2]), string(dropCapture[1]))
			dropPacketCount, err := strconv.Atoi(string(dropCapture[1]))
			if err != nil {
				glog.Errorf("Error parsing dropped packet count for policy %s: %v", string(dropCapture[2]), err)
				continue
			}

			policyType := policyTypeFromString(string(dropCapture[3]))
			dropChains[string(dropCapture[2])] = DropChain{
				PolicyType:  policyType,
				PacketCount: dropPacketCount,
			}
		}
	}

	scanner := bufio.NewScanner(&buf)
	lastTarget := ""
	for scanner.Scan() {
		// Read the next line of the output.
		line := scanner.Bytes()

		captures := appendRegexp.FindSubmatch(line)
		if captures == nil {
			// Skip any non-conforming lines
			continue
		}

		packetCount, err := strconv.Atoi(string(captures[1]))
		if err != nil {
			glog.Errorf("Error parsing packet count: %v", err)
			continue
		}

		isDrop := bytes.Contains(line, dropSlice)
		isAccept := bytes.Contains(line, acceptSlice)
		target := string(captures[4])

		if !(isDrop || isAccept) {
			lastTarget = target
			continue
		}

		typ := chainTypeFromString(string(captures[2]))
		iface := string(captures[3])

		workload, ok := interfaceToWorkload[iface]
		if !ok {
			glog.Errorf("Couldn't find workload for interface: %s", iface)
			continue
		}

		acceptType := Accept
		// If the current packet count is 0, and target points to a policy with a drop rule then
		// use the packet count from the drop rule.
		if packetCount == 0 {
			if v, ok := dropChains[lastTarget]; ok {
				glog.V(3).Infof("Using packet count %d from target %s instead of count %d", v.PacketCount, lastTarget, packetCount)
				packetCount = v.PacketCount
				acceptType = AcceptedDrop
			}
		}

		switch {
		case isDrop:
			result, err := buildResult(workload, Drop, typ, packetCount, target)
			if err != nil {
				glog.Errorf("Error building result from line '%s': %v", string(line), err)
				continue
			}
			results = append(results, result)
		case isAccept:
			// When we find an accept line, we care about the target on the previous line
			result, err := buildResult(workload, acceptType, typ, packetCount, lastTarget)
			if err != nil {
				glog.Errorf("Error building result from line %s: %v", string(line), err)
				continue
			}
			results = append(results, result)
		}
	}

	if scanner.Err() != nil {
		glog.Errorf("Failed to read iptables-save output: %v", scanner.Err())
		return nil, scanner.Err()
	}

	return results, nil
}

func buildResult(workload *apiv3.WorkloadEndpoint, countType CountType, chainType ChainType, packetCount int, target string) (*Result, error) {
	if countType == Drop && target != "DROP" {
		return nil, errors.New("drop count type but not a drop target")
	}

	ips := make([]string, 0, len(workload.Spec.IPNetworks))
	for _, str := range workload.Spec.IPNetworks {
		// remove pointless /32 suffix, if any
		ips = append(ips, strings.TrimSuffix(str, "/32"))
	}
	sort.Strings(ips)

	return &Result{
		PodName:      workload.Spec.Pod,
		PodNamespace: workload.Namespace,
		AppLabel:     workload.Labels["app"],
		PodIP:        strings.Join(ips, ","),
		ChainType:    chainType,
		CountType:    countType,
		PacketCount:  packetCount,
		Target:       target,
	}, nil
}
