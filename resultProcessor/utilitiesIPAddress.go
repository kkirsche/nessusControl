package nessusProcessor

import (
	"encoding/hex"
	"math/big"
	"net"
)

// IPv4ToInt converts an IPv4 net.IP object to a 64 bit integer.
func IPv4ToInt(ip net.IP) int64 {
	ipv4Int := big.NewInt(0)
	ipv4Int.SetBytes(ip.To4())
	return ipv4Int.Int64()
}

// IPv4ToHex converts an IPv4 net.IP object to a hexadecimal representaiton.
// This function is the equivalent of inet6_aton({{ ipv4 address }}) in MySQL.
func IPv4ToHex(ip net.IP) string {
	ipv4Int := big.NewInt(0)
	ipv4Int.SetBytes(ip.To4())
	ipHex := hex.EncodeToString(ipv4Int.Bytes())
	return ipHex
}

// IPv6ToHex converts an IPv6 net.IP object to a hexadecimal representaiton.
// This function is the equivalent of inet6_aton({{ ipv6 address }}) in MySQL.
func IPv6ToHex(ip net.IP) (string, error) {
	ipv6Int := big.NewInt(0)
	ipv6Int.SetBytes(ip.To16())
	ipHex := hex.EncodeToString(ipv6Int.Bytes())
	return ipHex, nil
}
