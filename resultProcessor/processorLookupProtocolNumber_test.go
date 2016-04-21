package nessusProcessor

import "testing"

func TestHopOptLookupProtocolNumberByProtocolString(t *testing.T) {
	hopOptInt := LookupProtocolNumberByProtocolString("HOPOPT")
	if hopOptInt != 0 {
		t.FailNow()
	}
}

func TestICMPLookupProtocolNumberByProtocolString(t *testing.T) {
	icmpInt := LookupProtocolNumberByProtocolString("ICMP")
	if icmpInt != 1 {
		t.FailNow()
	}
}

func TestIGMPLookupProtocolNumberByProtocolString(t *testing.T) {
	igmpInt := LookupProtocolNumberByProtocolString("IGMP")
	if igmpInt != 2 {
		t.FailNow()
	}
}

func TestGGPLookupProtocolNumberByProtocolString(t *testing.T) {
	ggpInt := LookupProtocolNumberByProtocolString("GGP")
	if ggpInt != 3 {
		t.FailNow()
	}
}

func TestIPV4LookupProtocolNumberByProtocolString(t *testing.T) {
	ipv4Int := LookupProtocolNumberByProtocolString("IPV4")
	if ipv4Int != 4 {
		t.FailNow()
	}
}

func TestSTLookupProtocolNumberByProtocolString(t *testing.T) {
	stInt := LookupProtocolNumberByProtocolString("ST")
	if stInt != 5 {
		t.FailNow()
	}
}

func TestTCPLookupProtocolNumberByProtocolString(t *testing.T) {
	tcpInt := LookupProtocolNumberByProtocolString("TCP")
	if tcpInt != 6 {
		t.FailNow()
	}
}

func TestUDPLookupProtocolNumberByProtocolString(t *testing.T) {
	udpInt := LookupProtocolNumberByProtocolString("UDP")
	if udpInt != 17 {
		t.FailNow()
	}
}

func TestInvalidProtocolLookupProtocolNumberByProtocolString(t *testing.T) {
	invalidInt := LookupProtocolNumberByProtocolString("This Isn't Anything")
	if invalidInt != -1 {
		t.FailNow()
	}
}
