package nessus

import (
	"encoding/json"
	"fmt"
	"net/http"
)

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
	c.debugln("ListScans(): Building list scans URL")
	url := fmt.Sprintf("https://%s:%s/scans/%d/pause", c.ip, c.port, scanID)

	statusCode, body, err := c.postWithJSON(httpClient, url, nil)
	if err != nil {
		return false, err
	}

	switch statusCode {
	case 200:
		c.debugln("ListScans(): Successfully retrieved list of scans.")
		return true, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return false, unmarshalError
		}
		c.debugln("ListScans(): Scans list could not be retrieved.")
		return false, fmt.Errorf("%s", err.Error)
	}
}
