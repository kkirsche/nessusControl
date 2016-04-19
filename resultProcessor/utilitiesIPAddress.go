package nessusProcessor

import (
	"math/big"
	"net"
)

// IPv4ToInt converts an IPv4 net.IP object to a 64 bit integer.
func IPv4ToInt(ip net.IP) int64 {
	ipv4Int := big.NewInt(0)
	ipv4Int.SetBytes(ip.To4())
	return ipv4Int.Int64()
}
