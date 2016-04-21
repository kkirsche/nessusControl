package nessusProcessor

import "strings"

// LookupProtocolNumberByProtocolString takes a string protocol, such as TCP
func LookupProtocolNumberByProtocolString(protocol string) int {
	// protocols contains minimal mappings between internet protocol
	// names and numbers for platforms that don't have a complete list of
	// protocol numbers.
	//
	// See http://www.iana.org/assignments/protocol-numbers
	var protocolMapping = map[string]int{
		"hopopt":      0,
		"icmp":        1,
		"igmp":        2,
		"ggp":         3,
		"ipv4":        4,
		"st":          5,
		"tcp":         6,
		"cbt":         7,
		"egp":         8,
		"igp":         9,
		"bbn-rcc-mon": 10,
		"nvp-ii":      11,
		"pup":         12,
		// No #13
		"emcon":      14,
		"xnet":       15,
		"chaos":      16,
		"udp":        17,
		"mux":        18,
		"hmp":        20,
		"prm":        21,
		"xnsidp":     22,
		"trunk1":     23,
		"trunk2":     24,
		"leaf1":      25,
		"leaf2":      26,
		"rdp":        27,
		"irtp":       28,
		"isotp4":     29,
		"netblt":     30,
		"mfensp":     31,
		"meritinp":   32,
		"dccp":       33,
		"3pc":        34,
		"idpr":       35,
		"xtp":        36,
		"ddp":        37,
		"idprcmtp":   38,
		"tppp":       39,
		"il":         40,
		"ipv6":       41,
		"sdrp":       42,
		"ipv6-route": 43,
		"ipv6-frag":  44,
		"gre":        47,
		"ipv6-icmp":  58,
	}

	if protocol == "" {
		return -1
	}

	lowerProto := strings.ToLower(protocol)

	if val, ok := protocolMapping[lowerProto]; ok {
		return val
	}
	return -1
}
