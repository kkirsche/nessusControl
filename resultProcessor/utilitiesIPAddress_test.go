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
