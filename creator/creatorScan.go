package nessusCreator

import (
	"encoding/json"
	"fmt"
	"github.com/kkirsche/nessusControl/api"
	"strings"
	"sync"
)

func (c *Creator) launchScan(createdScanResponseCh chan nessusAPI.CreateScanResponse) chan nessusAPI.LaunchedScan {
	c.debugln("launchScan(): Creating launched scan channel.")
	launchedScanCh := make(chan nessusAPI.LaunchedScan)
	var wg sync.WaitGroup

	for createdScanResponse := range createdScanResponseCh {
		wg.Add(1)
		c.debugln("launchScan(): Launching scan " + createdScanResponse.Scan.Name)
		go func(c *Creator, wg *sync.WaitGroup, launchedScanCh chan nessusAPI.LaunchedScan, createdScanResponse nessusAPI.CreateScanResponse) {
			launchedScan, err := c.apiClient.LaunchScan(c.httpClient, createdScanResponse.Scan.ID)
			if err != nil {
				c.debugln("launchScan(): Failed to launch scan with error " + err.Error())
			} else {
				launchedScanCh <- launchedScan
			}
			wg.Done()
		}(c, &wg, launchedScanCh, createdScanResponse)
	}

	go func(wg *sync.WaitGroup, launchedScanCh chan nessusAPI.LaunchedScan) {
		wg.Wait()
		c.debugln("launchScan(): Closing launched scan channel.")
		close(launchedScanCh)
	}(&wg, launchedScanCh)

	return launchedScanCh
}

func (c *Creator) createScan(createScanJSONCh chan nessusAPI.CreateScan) chan nessusAPI.CreateScanResponse {
	var wg sync.WaitGroup
	c.debugln("createScan(): Creating scans from JSON")
	createScanResponseCh := make(chan nessusAPI.CreateScanResponse)

	for createScanJSON := range createScanJSONCh {
		c.debugln("createScan(): Creating scan")
		wg.Add(1)
		go func(c *Creator, createScanJSON nessusAPI.CreateScan, wg *sync.WaitGroup) {
			marshalledJSON, err := json.Marshal(createScanJSON)
			if err != nil {
				wg.Done()
				return
			}

			createdScan, err := c.apiClient.CreateScan(c.httpClient, string(marshalledJSON))
			if err != nil {
				c.debugln("createScan(): Failed to create scan with error: " + err.Error())
			} else {
				c.debugln("createScan(): Successfully created scan " + createdScan.Scan.Name)
				createScanResponseCh <- createdScan
			}
			wg.Done()
		}(c, createScanJSON, &wg)
	}

	go func(wg *sync.WaitGroup, createScanResponseCh chan nessusAPI.CreateScanResponse) {
		wg.Wait()
		c.debugln("createScan(): Closing create scan channel.")
		close(createScanResponseCh)
	}(&wg, createScanResponseCh)

	return createScanResponseCh
}

// buildCreateScanJSON is used to create a struct which can be marshalled into
// JSON and sent to a remote Nessus server.
func (c *Creator) buildCreateScanJSON(requestScanch chan RequestedScan) chan nessusAPI.CreateScan {
	c.debugln("buildCreateScanJSON(): Building JSON for Create Scan")
	var wg sync.WaitGroup
	createScanJSONch := make(chan nessusAPI.CreateScan)

	for requestedScan := range requestScanch {
		wg.Add(1)
		c.debugln("buildCreateScanJSON(): Building JSON for request ID #" + requestedScan.RequestID)
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
		}(requestedScan, &wg, createScanJSONch)
	}

	go func(wg *sync.WaitGroup, createScanJSONch chan nessusAPI.CreateScan) {
		wg.Wait()
		c.debugln("buildCreateScanJSON(): Closing create scan JSON channel.")
		close(createScanJSONch)
	}(&wg, createScanJSONch)

	return createScanJSONch
}

// scanMethodToPolicyID takes a method which was extracted from
// processRequestedScanFile() and returns the corresponding Nessus Policy ID.
func (c *Creator) scanMethodToPolicyID(method string) string {
	c.debugln("scanMethodToPolicyID(): Determining policy ID from scan method")
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
