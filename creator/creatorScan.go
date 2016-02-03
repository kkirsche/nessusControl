package nessusCreator

import (
	"encoding/json"
	"fmt"
	"github.com/kkirsche/nessusControl/api"
	"strings"
	"sync"
	"time"
)

func (c *Creator) saveLaunchedScan(launchedScanCh chan ScanData) error {
	if c.sqliteDB == nil {
		return fmt.Errorf("No database connection was found.")
	}

	c.debugln("Creating active_scans table in SQLite database if it doesn't exist already.")
	_, err := c.sqliteDB.Exec("CREATE TABLE IF NOT EXISTS active_scans (request_id bigint, method varchar(200), scan_uuid varchar(250), scan_id integer, scan_starttime varchar(255));")
	if err != nil {
		return err
	}

	for launchedScanData := range launchedScanCh {
		c.debugln("Saving scan data for requested scan #" + launchedScanData.RequestedScan.RequestID)
		_, err = c.sqliteDB.Exec("INSERT INTO active_scans (request_id, method, scan_uuid, scan_starttime) VALUES ($a, $b, $c, $d, $e)", "this", launchedScanData.RequestedScan.RequestID, launchedScanData.RequestedScan.Method, launchedScanData.LaunchedScan.ScanUUID, launchedScanData.ScanStartTime)
		if err != nil {
			return err
		}
	}

	c.debugln("Finished saving scan data.")

	return nil
}

func (c *Creator) launchScan(createdScanResponseCh chan ScanData) chan ScanData {
	c.debugln("launchScan(): Creating launched scan channel.")
	launchedScanCh := make(chan ScanData)
	var wg sync.WaitGroup

	for createdScanResponseData := range createdScanResponseCh {
		wg.Add(1)
		c.debugln("launchScan(): Launching scan " + createdScanResponseData.CreatedScan.Scan.Name)
		go func(c *Creator, wg *sync.WaitGroup, launchedScanCh chan ScanData, createdScanResponseData ScanData) {
			launchedScan, err := c.apiClient.LaunchScan(c.httpClient, createdScanResponseData.CreatedScan.Scan.ID)
			if err != nil {
				c.debugln("launchScan(): Failed to launch scan with error " + err.Error())
			} else {
				createdScanResponseData.LaunchedScan = launchedScan
				createdScanResponseData.ScanStartTime = time.Now().UTC().Format(time.RFC3339)
				launchedScanCh <- createdScanResponseData
			}
			wg.Done()
		}(c, &wg, launchedScanCh, createdScanResponseData)
	}

	go func(wg *sync.WaitGroup, launchedScanCh chan ScanData) {
		wg.Wait()
		c.debugln("launchScan(): Closing launched scan channel.")
		close(launchedScanCh)
	}(&wg, launchedScanCh)

	return launchedScanCh
}

func (c *Creator) createScan(createScanJSONCh chan ScanData) chan ScanData {
	var wg sync.WaitGroup
	c.debugln("createScan(): Creating scans from JSON")
	createScanResponseCh := make(chan ScanData)

	for createScanJSONData := range createScanJSONCh {
		c.debugln("createScan(): Creating scan")
		wg.Add(1)
		go func(c *Creator, createScanJSONData ScanData, wg *sync.WaitGroup) {
			marshalledJSON, err := json.Marshal(createScanJSONData.CreateScanJSON)
			if err != nil {
				wg.Done()
				return
			}

			createdScan, err := c.apiClient.CreateScan(c.httpClient, string(marshalledJSON))
			if err != nil {
				c.debugln("createScan(): Failed to create scan with error: " + err.Error())
			} else {
				c.debugln("createScan(): Successfully created scan " + createdScan.Scan.Name)
				createScanJSONData.CreatedScan = createdScan
				createScanResponseCh <- createScanJSONData
			}
			wg.Done()
		}(c, createScanJSONData, &wg)
	}

	go func(wg *sync.WaitGroup, createScanResponseCh chan ScanData) {
		wg.Wait()
		c.debugln("createScan(): Closing create scan channel.")
		close(createScanResponseCh)
	}(&wg, createScanResponseCh)

	return createScanResponseCh
}

// buildCreateScanJSON is used to create a struct which can be marshalled into
// JSON and sent to a remote Nessus server.
func (c *Creator) buildCreateScanJSON(requestScanch chan ScanData) chan ScanData {
	c.debugln("buildCreateScanJSON(): Building JSON for Create Scan")
	var wg sync.WaitGroup
	createScanJSONch := make(chan ScanData)

	for requestedScanData := range requestScanch {
		wg.Add(1)
		c.debugln("buildCreateScanJSON(): Building JSON for request ID #" + requestedScanData.RequestedScan.RequestID)
		go func(requestedScanData ScanData, wg *sync.WaitGroup, createScanJSONch chan ScanData) {
			scanNameAndDescription := fmt.Sprintf("Scan Request #%s, Method: %s", requestedScanData.RequestedScan.RequestID, requestedScanData.RequestedScan.Method)
			targets := strings.Join(requestedScanData.RequestedScan.TargetIPs, " ")
			policyID := c.scanMethodToPolicyID(requestedScanData.RequestedScan.Method)

			requestedScanData.CreateScanJSON = nessusAPI.CreateScan{
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

			createScanJSONch <- requestedScanData
			wg.Done()
		}(requestedScanData, &wg, createScanJSONch)
	}

	go func(wg *sync.WaitGroup, createScanJSONch chan ScanData) {
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
