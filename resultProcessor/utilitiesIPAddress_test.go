package nessusProcessor

import (
	"net"
	"testing"
)

func TestIPv4ToInt(t *testing.T) {
	ip := net.ParseIP("10.0.5.9")
	if ip == nil {
		t.FailNow()
	}

	ipInt := IPv4ToInt(ip)
	if ipInt != 167773449 {
		t.FailNow()
	}
}

func TestIPv4ToHex(t *testing.T) {
	ip := net.ParseIP("10.0.5.9")
	if ip == nil {
		t.FailNow()
	}

	ipHex := IPv4ToHex(ip)
	if ipHex != "0a000509" {
		t.FailNow()
	}
}

func TestIPv6ToHex(t *testing.T) {
	ip := net.ParseIP("fdfe::5a55:caff:fefa:9089")

	ipHex, err := IPv6ToHex(ip)
	if err != nil {
		t.FailNow()
	}

	if ipHex != "fdfe0000000000005a55cafffefa9089" {
		t.FailNow()
	}
}
