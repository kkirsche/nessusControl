package nessusCreator

import (
	"fmt"
	"github.com/kkirsche/nessusControl/api"
	"strings"
	"sync"
)

// buildCreateScanJSON is used to create a struct which can be marshalled into
// JSON and sent to a remote Nessus server.
func (c *Creator) buildCreateScanJSON(requestScanch chan RequestedScan) chan nessusAPI.CreateScan {
	createScanJSONch := make(chan nessusAPI.CreateScan)
	wg := new(sync.WaitGroup)

	for requestedScan := range requestScanch {
		wg.Add(1)
		go func(requestedScan RequestedScan, wg *sync.WaitGroup, createScanJSONch chan nessusAPI.CreateScan) {
			scanNameAndDescription := fmt.Sprintf("Scan Request #%s, Method: %s", requestedScan.RequestID, requestedScan.Method)
			targets := strings.Join(requestedScan.TargetIPs, " ")
			policyID := c.scanMethodToPolicyID(requestedScan.Method)

			createScanJSONch <- nessusAPI.CreateScan{
				UUID: "ab4bacd2-05f6-425c-9d79-3ba3940ad1c24e51e1f403febe40",
				Settings: nessusAPI.CreateScanSettings{
					Name:        scanNameAndDescription,
					Description: scanNameAndDescription,
					FolderID:    "65",
					ScannerID:   "1",
					PolicyID:    policyID,
					TextTargets: targets,
					Launch:      "ONETIME",
					Enabled:     false,
					LaunchNow:   false,
					Emails:      "",
				},
			}
			wg.Done()
		}(requestedScan, wg, createScanJSONch)
	}

	go func(wg *sync.WaitGroup, createScanJSONch chan nessusAPI.CreateScan) {
		wg.Wait()
		close(createScanJSONch)
	}(wg, createScanJSONch)

	return createScanJSONch
}

// scanMethodToPolicyID takes a method which was extracted from
// processRequestedScanFile() and returns the corresponding Nessus Policy ID.
func (c *Creator) scanMethodToPolicyID(method string) string {
	switch method {
	case "allportswithping":
		return "52"
	case "allportsnoping":
		return "53"
	case "atomic":
		return "54"
	case "pci":
		return "55"
	default:
		return "19"
	}
}
