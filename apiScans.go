package nessus

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// ConfigureScan changes the schedule or policy parameters of a scan.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) ConfigureScan(httpClient *http.Client, scanID int, configureScanJSON string) (CreateScanResponse, error) {
	c.debugln("ConfigureScan(): Building configure scan URL")
	url := fmt.Sprintf("https://%s:%s/scans/%d", c.ip, c.port, scanID)

	statusCode, body, err := c.putWithJSON(httpClient, url, []byte(configureScanJSON))
	if err != nil {
		return CreateScanResponse{}, err
	}

	switch statusCode {
	case 200:
		var createdScan CreateScanResponse
		err = json.Unmarshal(body, &createdScan)
		if err != nil {
			return CreateScanResponse{}, err
		}
		c.debugln("ConfigureScan(): Successfully configured scan.")
		return createdScan, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return CreateScanResponse{}, unmarshalError
		}
		c.debugln("ConfigureScan(): Could not configure scan.")
		return CreateScanResponse{}, fmt.Errorf("%s", err.Error)
	}
}

// CreateScan creates a new scan.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) CreateScan(httpClient *http.Client, newScanJSON string) (CreateScanResponse, error) {
	c.debugln("CreateScan(): Building create scan URL")
	url := fmt.Sprintf("https://%s:%s/scans", c.ip, c.port)

	statusCode, body, err := c.postWithJSON(httpClient, url, []byte(newScanJSON))
	if err != nil {
		return CreateScanResponse{}, err
	}

	switch statusCode {
	case 200:
		var createdScan CreateScanResponse
		err = json.Unmarshal(body, &createdScan)
		if err != nil {
			return CreateScanResponse{}, err
		}
		c.debugln("CreateScan(): Successfully created scan.")
		return createdScan, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return CreateScanResponse{}, unmarshalError
		}
		c.debugln("CreateScan(): Could not create scan.")
		return CreateScanResponse{}, fmt.Errorf("%s", err.Error)
	}
}

// DeleteScan deletes a scan. NOTE: Scans in running, paused or stopping
// states can not be deleted.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) DeleteScan(httpClient *http.Client, scanID int) (bool, error) {
	c.debugln("DeleteScan(): Building delete scan URL")
	url := fmt.Sprintf("https://%s:%s/scans/%d", c.ip, c.port, scanID)

	statusCode, body, err := c.delete(httpClient, url)
	if err != nil {
		return false, err
	}

	switch statusCode {
	case 200:
		c.debugln("DeleteScan(): Successfully deleted scan.")
		return true, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return false, unmarshalError
		}
		c.debugln("DeleteScan(): Scan could not be deleted.")
		return false, fmt.Errorf("%s", err.Error)
	}
}

// DeleteScanHistory deletes historical results from a scan.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) DeleteScanHistory(httpClient *http.Client, scanID, historyID int) (bool, error) {
	c.debugln("DeleteScanHistory(): Building delete scan history URL")
	url := fmt.Sprintf("https://%s:%s/scans/%d/history/%d", c.ip, c.port, scanID, historyID)

	statusCode, body, err := c.delete(httpClient, url)
	if err != nil {
		return false, err
	}

	switch statusCode {
	case 200:
		c.debugln("DeleteScanHistory(): Successfully deleted scan history.")
		return true, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return false, unmarshalError
		}
		c.debugln("PauseScan(): Scan history could not be deleted.")
		return false, fmt.Errorf("%s", err.Error)
	}
}

// ScanDetails downloads an exported scan.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) ScanDetails(httpClient *http.Client, scanID int) (ScanDetails, error) {
	c.debugln("ScanDetails(): Building scan details URL.")
	url := fmt.Sprintf("https://%s:%s/scans/%d", c.ip, c.port, scanID)

	statusCode, body, err := c.get(httpClient, url)
	if err != nil {
		return ScanDetails{}, err
	}

	switch statusCode {
	case 200:
		var scanDetails ScanDetails
		err = json.Unmarshal(body, &scanDetails)
		if err != nil {
			return ScanDetails{}, err
		}
		c.debugln("ScanDetails(): Successfully retrieved scan details.")
		return scanDetails, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return ScanDetails{}, unmarshalError
		}
		c.debugln("ScanDetails(): Scan details not be retrieved.")
		return ScanDetails{}, fmt.Errorf("%s", err.Error)
	}
}

// DownloadScan downloads an exported scan.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) DownloadScan(httpClient *http.Client, scanID, fileID int) (string, error) {
	c.debugln("DownloadScan(): Building download scan URL.")
	url := fmt.Sprintf("https://%s:%s/scans/%d/export/%d/download", c.ip, c.port, scanID, fileID)

	statusCode, body, err := c.get(httpClient, url)
	if err != nil {
		return "", err
	}

	switch statusCode {
	case 200:
		c.debugln("DownloadScan(): Successfully downloaded scan.")
		return string(body), nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return "", unmarshalError
		}
		c.debugln("DownloadScan(): Scan could not be downloaded.")
		return "", fmt.Errorf("%s", err.Error)
	}
}

// ExportScan exports the given scan.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) ExportScan(httpClient *http.Client, scanID int, exportSettingsJSON string) (ExportedScan, error) {
	c.debugln("ExportScan(): Building export scan URL")
	url := fmt.Sprintf("https://%s:%s/scans/%d/export", c.ip, c.port, scanID)

	statusCode, body, err := c.postWithJSON(httpClient, url, []byte(exportSettingsJSON))
	if err != nil {
		return ExportedScan{}, err
	}

	switch statusCode {
	case 200:
		var exportedScan ExportedScan
		err = json.Unmarshal(body, &exportedScan)
		if err != nil {
			return ExportedScan{}, err
		}
		c.debugln("ExportScan(): Successfully initiated scan export.")
		return exportedScan, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return ExportedScan{}, unmarshalError
		}
		c.debugln("ExportScan(): Scan export could not be initiated.")
		return ExportedScan{}, fmt.Errorf("%s", err.Error)
	}
}

// ScanExportStatus checks the file status of an exported scan.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) ScanExportStatus(httpClient *http.Client, scanID, fileID int) (ScanExportStatus, error) {
	c.debugln("ScanExportStatus(): Building export scan status URL")
	url := fmt.Sprintf("https://%s:%s/scans/%d/export/%d/status", c.ip, c.port, scanID, fileID)

	statusCode, body, err := c.get(httpClient, url)
	if err != nil {
		return ScanExportStatus{}, err
	}

	switch statusCode {
	case 200:
		var exportStatus ScanExportStatus
		err = json.Unmarshal(body, &exportStatus)
		if err != nil {
			return ScanExportStatus{}, err
		}
		c.debugln("ScanExportStatus(): Successfully retrieved scan export status.")
		return exportStatus, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return ScanExportStatus{}, unmarshalError
		}
		c.debugln("ScanExportStatus(): Scan export status not be retrieved.")
		return ScanExportStatus{}, fmt.Errorf("%s", err.Error)
	}
}

// LaunchScan launches a scan.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) LaunchScan(httpClient *http.Client, scanID int) (LaunchedScan, error) {
	c.debugln("LaunchScan(): Building launch scan URL")
	url := fmt.Sprintf("https://%s:%s/scans/%d/launch", c.ip, c.port, scanID)

	statusCode, body, err := c.postWithJSON(httpClient, url, nil)
	if err != nil {
		return LaunchedScan{}, err
	}

	switch statusCode {
	case 200:
		var launchedScan LaunchedScan
		err = json.Unmarshal(body, &launchedScan)
		if err != nil {
			return LaunchedScan{}, err
		}
		c.debugln("Launch(): Successfully launched scan.")
		return launchedScan, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return LaunchedScan{}, unmarshalError
		}
		c.debugln("LaunchScan(): Scan could not be launched.")
		return LaunchedScan{}, fmt.Errorf("%s", err.Error)
	}
}

// ListScans returns the scan list.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) ListScans(httpClient *http.Client) (ScanList, error) {
	c.debugln("ListScans(): Building list scans URL")
	url := fmt.Sprintf("https://%s:%s/scans", c.ip, c.port)

	statusCode, body, err := c.get(httpClient, url)
	if err != nil {
		return ScanList{}, err
	}

	switch statusCode {
	case 200:
		var scanList ScanList
		err = json.Unmarshal(body, &scanList)
		if err != nil {
			return ScanList{}, err
		}
		c.debugln("ListScans(): Successfully retrieved list of scans.")
		return scanList, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return ScanList{}, unmarshalError
		}
		c.debugln("ListScans(): Scans list could not be retrieved.")
		return ScanList{}, fmt.Errorf("%s", err.Error)
	}
}

// PauseScan pauses a scan.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) PauseScan(httpClient *http.Client, scanID int) (bool, error) {
	c.debugln("PauseScan(): Building pause scan URL")
	url := fmt.Sprintf("https://%s:%s/scans/%d/pause", c.ip, c.port, scanID)

	statusCode, body, err := c.postWithJSON(httpClient, url, nil)
	if err != nil {
		return false, err
	}

	switch statusCode {
	case 200:
		c.debugln("PauseScan(): Successfully paused scan.")
		return true, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return false, unmarshalError
		}
		c.debugln("PauseScan(): Scan could not be paused.")
		return false, fmt.Errorf("%s", err.Error)
	}
}

// ToggleScanResultReadStatus changes the read status of a scan. If read is true,
// the scan result have been read.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) ToggleScanResultReadStatus(httpClient *http.Client, scanID int, read bool) (bool, error) {
	c.debugln("ToggleScanResultReadStatus(): Building toggle scan result read status URL")
	url := fmt.Sprintf("https://%s:%s/scans/%d/status", c.ip, c.port, scanID)

	readJSON := fmt.Sprintf(`{"read":%t}`, read)

	statusCode, body, err := c.putWithJSON(httpClient, url, []byte(readJSON))
	if err != nil {
		return false, err
	}

	switch statusCode {
	case 200:
		c.debugln("ToggleScanResultReadStatus(): Successfully toggled scan read status.")
		return true, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return false, unmarshalError
		}
		c.debugln("ToggleScanResultReadStatus(): Scan read status could not be toggled.")
		return false, fmt.Errorf("%s", err.Error)
	}
}

// ResumeScan stops a scan.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) ResumeScan(httpClient *http.Client, scanID int) (bool, error) {
	c.debugln("ResumeScan(): Building resume scan URL")
	url := fmt.Sprintf("https://%s:%s/scans/%d/resume", c.ip, c.port, scanID)

	statusCode, body, err := c.postWithJSON(httpClient, url, nil)
	if err != nil {
		return false, err
	}

	switch statusCode {
	case 200:
		c.debugln("ResumeScan(): Successfully resumed scan.")
		return true, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return false, unmarshalError
		}
		c.debugln("ResumeScan(): Scan could not be resumed.")
		return false, fmt.Errorf("%s", err.Error)
	}
}

// ToggleScheduledScan enables or disables a scan schedule.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) ToggleScheduledScan(httpClient *http.Client, scanID int, enabled bool) (ToggleScheduledScan, error) {
	c.debugln("ToggleScheduledScan(): Building toggle scheduled scan URL")
	url := fmt.Sprintf("https://%s:%s/scans/%d/schedule", c.ip, c.port, scanID)

	toggleJSON := fmt.Sprintf(`{"enabled": %t}`, enabled)

	statusCode, body, err := c.postWithJSON(httpClient, url, []byte(toggleJSON))
	if err != nil {
		return ToggleScheduledScan{}, err
	}

	switch statusCode {
	case 200:
		var toggledScan ToggleScheduledScan
		err = json.Unmarshal(body, &toggledScan)
		if err != nil {
			return ToggleScheduledScan{}, err
		}
		c.debugln("ToggleScheduledScan(): Successfully toggled scan schedule.")
		return toggledScan, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return ToggleScheduledScan{}, unmarshalError
		}
		c.debugln("ToggleScheduledScan(): Scan schedule could not be toggled.")
		return ToggleScheduledScan{}, fmt.Errorf("%s", err.Error)
	}
}

// StopScan stops a scan.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) StopScan(httpClient *http.Client, scanID int) (bool, error) {
	c.debugln("StopScan(): Building stop scan URL")
	url := fmt.Sprintf("https://%s:%s/scans/%d/stop", c.ip, c.port, scanID)

	statusCode, body, err := c.postWithJSON(httpClient, url, nil)
	if err != nil {
		return false, err
	}

	switch statusCode {
	case 200:
		c.debugln("StopScan(): Successfully stopped scan.")
		return true, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return false, unmarshalError
		}
		c.debugln("StopScan(): Scan could not be stopped.")
		return false, fmt.Errorf("%s", err.Error)
	}
}

// ListScanTimezones returns the timezone list for creating a scan.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) ListScanTimezones(httpClient *http.Client) (ScanTimezones, error) {
	c.debugln("ScanTimezones(): Building scan timezone list URL")
	url := fmt.Sprintf("https://%s:%s/scans/timezones", c.ip, c.port)

	statusCode, body, err := c.get(httpClient, url)
	if err != nil {
		return ScanTimezones{}, err
	}

	switch statusCode {
	case 200:
		var scanTimezones ScanTimezones
		err = json.Unmarshal(body, &scanTimezones)
		if err != nil {
			return ScanTimezones{}, err
		}
		c.debugln("ScanTimezones(): Successfully retrieved list of scan timezones.")
		return scanTimezones, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return ScanTimezones{}, unmarshalError
		}
		c.debugln("ScanTimezones(): Scan timezones list could not be retrieved.")
		return ScanTimezones{}, fmt.Errorf("%s", err.Error)
	}
}
