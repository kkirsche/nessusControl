package nessus

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// PluginFamilies returns the list of plugin families.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) PluginFamilies(httpClient *http.Client) (PluginFamilies, error) {
	c.debugln("PluginFamilies(): Building plugin families URL")
	url := fmt.Sprintf("https://%s:%s/plugins/families", c.ip, c.port)

	statusCode, body, err := c.get(httpClient, url)
	if err != nil {
		return PluginFamilies{}, err
	}

	switch statusCode {
	case 200:
		var families PluginFamilies
		err = json.Unmarshal(body, &families)
		if err != nil {
			return PluginFamilies{}, err
		}
		c.debugln("PluginFamilies(): Successfully retrieved plugin families.")
		return families, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return PluginFamilies{}, unmarshalError
		}
		c.debugln("PluginFamilies(): Plugin families could not be retrieved.")
		return PluginFamilies{}, fmt.Errorf("%s", err.Error)
	}
}
