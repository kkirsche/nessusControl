package nessus

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// ListScanners returns the scanner list.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) ListScanners(httpClient *http.Client) (ListScannersResponse, error) {
	c.debugln("ListScanners(): Building list scanners URL")
	url := fmt.Sprintf("https://%s:%s/scanners", c.ip, c.port)

	statusCode, body, err := c.get(httpClient, url)
	if err != nil {
		return ListScannersResponse{}, err
	}

	switch statusCode {
	case 200:
		var scanners ListScannersResponse
		err := json.Unmarshal(body, &scanners)
		if err != nil {
			return ListScannersResponse{}, err
		}
		c.debugln("ListScanners(): Successfully retrieved list of scanners.")
		return scanners, nil
	default:
		var err ErrorResponse
		unmarErr := json.Unmarshal(body, &err)
		if unmarErr != nil {
			return ListScannersResponse{}, unmarErr
		}
		c.debugln("ListScanners(): Scanners list could not be retrieved.")
		return ListScannersResponse{}, fmt.Errorf("%s", err.Error)
	}
}
