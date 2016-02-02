package nessus

import (
	"encoding/json"
	"fmt"
	"net/http"
)

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
