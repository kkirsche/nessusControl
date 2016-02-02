package nessusAPI

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

// PluginFamilyDetails returns the list of plugins in a family.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) PluginFamilyDetails(httpClient *http.Client, pluginFamilyID int) (PluginFamilyDetails, error) {
	c.debugln("PluginFamilyDetails(): Building plugin family details URL")
	url := fmt.Sprintf("https://%s:%s/plugins/families/%d", c.ip, c.port, pluginFamilyID)

	statusCode, body, err := c.get(httpClient, url)
	if err != nil {
		return PluginFamilyDetails{}, err
	}

	switch statusCode {
	case 200:
		var familyDetails PluginFamilyDetails
		err = json.Unmarshal(body, &familyDetails)
		if err != nil {
			return PluginFamilyDetails{}, err
		}
		c.debugln("PluginFamilyDetails(): Successfully retrieved plugin family details.")
		return familyDetails, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return PluginFamilyDetails{}, unmarshalError
		}
		c.debugln("PluginFamilyDetails(): Plugin family details could not be retrieved.")
		return PluginFamilyDetails{}, fmt.Errorf("%s", err.Error)
	}
}

// PluginDetails returns the details for a given plugin.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) PluginDetails(httpClient *http.Client, pluginID int) (PluginDetails, error) {
	c.debugln("PluginDetails(): Building plugin details URL")
	url := fmt.Sprintf("https://%s:%s/plugins/plugin/%d", c.ip, c.port, pluginID)

	statusCode, body, err := c.get(httpClient, url)
	if err != nil {
		return PluginDetails{}, err
	}

	switch statusCode {
	case 200:
		var pluginDetails PluginDetails
		err = json.Unmarshal(body, &pluginDetails)
		if err != nil {
			return PluginDetails{}, err
		}
		c.debugln("PluginFamilyDetails(): Successfully retrieved plugin details.")
		return pluginDetails, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return PluginDetails{}, unmarshalError
		}
		c.debugln("PluginFamilyDetails(): Plugin details could not be retrieved.")
		return PluginDetails{}, fmt.Errorf("%s", err.Error)
	}
}
