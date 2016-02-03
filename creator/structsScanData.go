package nessusCreator

import (
	"github.com/kkirsche/nessusControl/api"
)

// ScanData holds the information about a scan throughout the pipeline
type ScanData struct {
	RequestedScan  RequestedScan
	CreateScanJSON nessusAPI.CreateScan
	CreatedScan    nessusAPI.CreateScanResponse
	LaunchedScan   nessusAPI.LaunchedScan
	ScanStartTime  string
}

// RequestedScan holds the information from when the scan was requested
type RequestedScan struct {
	Method    string   `json:"method" xml:"method"`
	RequestID string   `json:"request_id" xml:"request_id"`
	TargetIPs []string `json:"target_ips" xml:"target_ips"`
}
