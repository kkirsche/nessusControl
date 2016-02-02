package nessusCreator

// RequestedScan holds the information from when the scan was requested
type RequestedScan struct {
	Method    string   `json:"method" xml:"method"`
	RequestID string   `json:"request_id" xml:"request_id"`
	TargetIPs []string `json:"target_ips" xml:"target_ips"`
}
