package nessusAPI

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// ServerProperties returns the Nessus server version and other properties.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) ServerProperties(httpClient *http.Client) (ServerPropertiesResponse, error) {
	c.debugln("ServerProperties(): Building server properties URL")
	url := fmt.Sprintf("https://%s:%s/server/properties", c.ip, c.port)

	statusCode, body, err := c.get(httpClient, url)
	if err != nil {
		return ServerPropertiesResponse{}, err
	}

	switch statusCode {
	case 200:
		var properties ServerPropertiesResponse
		err := json.Unmarshal(body, &properties)
		if err != nil {
			return ServerPropertiesResponse{}, err
		}
		c.debugln("ServerProperties(): Successfully retrieved server properties.")
		return properties, nil
	default:
		var err ErrorResponse
		unmarErr := json.Unmarshal(body, &err)
		if unmarErr != nil {
			return ServerPropertiesResponse{}, unmarErr
		}
		c.debugln("ServerProperties(): Server properties could not be retrieved.")
		return ServerPropertiesResponse{}, fmt.Errorf("%s", err.Error)
	}
}

// ServerStatus returns the Nessus server status.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) ServerStatus(httpClient *http.Client) (ServerStatusResponse, error) {
	c.debugln("ServerStatus(): Building server status URL")
	url := fmt.Sprintf("https://%s:%s/server/status", c.ip, c.port)

	statusCode, body, err := c.get(httpClient, url)
	if err != nil {
		return ServerStatusResponse{}, err
	}

	switch statusCode {
	case 200:
		var status ServerStatusResponse
		err := json.Unmarshal(body, &status)
		if err != nil {
			return ServerStatusResponse{}, err
		}
		c.debugln("ServerStatus(): Successfully retrieved server status.")
		return status, nil
	default:
		var err ErrorResponse
		unmarErr := json.Unmarshal(body, &err)
		if unmarErr != nil {
			return ServerStatusResponse{}, unmarErr
		}
		c.debugln("ServerStatus(): Server status could not be retrieved.")
		return ServerStatusResponse{}, fmt.Errorf("%s", err.Error)
	}
}
