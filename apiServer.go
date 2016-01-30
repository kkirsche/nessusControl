package nessus

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// ServerProperties returns the Nessus server version and other properties.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) ServerProperties(httpClient *http.Client) (serverPropertiesResponse, error) {
	c.debugln("ServerProperties(): Building server properties URL")
	url := fmt.Sprintf("https://%s:%s/server/properties", c.ip, c.port)

	statusCode, body, err := c.get(httpClient, url)
	if err != nil {
		return serverPropertiesResponse{}, err
	}

	switch statusCode {
	case 200:
		var properties serverPropertiesResponse
		json.Unmarshal(body, &properties)
		c.debugln("ServerProperties(): Successfully retrieved session.")
		return properties, nil
	default:
		var err errorResponse
		json.Unmarshal(body, &err)
		c.debugln("ServerProperties(): Server properties could not be retrieved.")
		return serverPropertiesResponse{}, fmt.Errorf("%s", err.Error)
	}
}
