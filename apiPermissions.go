package nessus

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// ChangePermissions changes the permissions for an object. Allowed objectType
// values are "policy", "scan", "scanner", "agent-group", "scanner-pool", and
// "connector".
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) ChangePermissions(httpClient *http.Client, objectType string, objectID int, updatedPermissions string) (bool, error) {
	c.debugln("ListPermissions(): Building list permissions URL")
	url := fmt.Sprintf("https://%s:%s/permissions/%s/%d", c.ip, c.port, objectType, objectID)

	statusCode, body, err := c.putWithJSON(httpClient, url, []byte(updatedPermissions))
	if err != nil {
		return false, err
	}

	switch statusCode {
	case 200:
		c.debugln("ListPermissions(): Successfully retrieved object's permissions.")
		return true, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return false, unmarshalError
		}
		c.debugln("ListPermissions(): Object's permissions could not be retrieved.")
		return false, fmt.Errorf("%s", err.Error)
	}
}

// ListPermissions returns the current object's permissions. Allowed objectType
// values are "policy", "scan", "scanner", "agent-group", "scanner-pool", and
// "connector".
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) ListPermissions(httpClient *http.Client, objectType string, objectID int) (Permissions, error) {
	c.debugln("ListPermissions(): Building list permissions URL")
	url := fmt.Sprintf("https://%s:%s/permissions/%s/%d", c.ip, c.port, objectType, objectID)

	statusCode, body, err := c.get(httpClient, url)
	if err != nil {
		return Permissions{}, err
	}

	switch statusCode {
	case 200:
		var permissions Permissions
		err = json.Unmarshal(body, &permissions)
		if err != nil {
			return Permissions{}, err
		}
		c.debugln("ListPermissions(): Successfully retrieved object's permissions.")
		return permissions, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return Permissions{}, unmarshalError
		}
		c.debugln("ListPermissions(): Object's permissions could not be retrieved.")
		return Permissions{}, fmt.Errorf("%s", err.Error)
	}
}
