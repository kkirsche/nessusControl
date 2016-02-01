package nessus

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// ViewProxy returns the proxy settings.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) ViewProxy(httpClient *http.Client) (ViewProxyResponse, error) {
	c.debugln("ViewProxy(): Building list scanners URL")
	url := fmt.Sprintf("https://%s:%s/settings/network/proxy", c.ip, c.port)

	statusCode, body, err := c.get(httpClient, url)
	if err != nil {
		return ViewProxyResponse{}, err
	}

	switch statusCode {
	case 200:
		var proxySettings ViewProxyResponse
		err = json.Unmarshal(body, &proxySettings)
		if err != nil {
			fmt.Println(err)
			return ViewProxyResponse{}, err
		}
		c.debugln("ViewProxy(): Successfully retrieved proxy settings.")
		return proxySettings, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return ViewProxyResponse{}, unmarshalError
		}
		c.debugln("ViewProxy(): Proxy settings could not be retrieved.")
		return ViewProxyResponse{}, fmt.Errorf("%s", err.Error)
	}
}

// ChangeProxy changes the proxy settings.
// It requires an http.Client pointer to make the request to Nessus. It also
// requires the JSON object that will be used to submit the change as a string
// argument.
func (c *Client) ChangeProxy(httpClient *http.Client, changeJSON string) (bool, error) {
	c.debugln("ChangeProxy(): Building change proxy settings URL")
	url := fmt.Sprintf("https://%s:%s/settings/network/proxy", c.ip, c.port)

	marshalledChangeJSON, err := json.Marshal(changeJSON)
	if err != nil {
		return false, err
	}

	statusCode, body, err := c.putWithJSON(httpClient, url, marshalledChangeJSON)
	if err != nil {
		return false, err
	}

	switch statusCode {
	case 200:
		c.debugln("ChangeProxy(): Successfully changed proxy settings.")
		return true, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return false, unmarshalError
		}
		c.debugln("ChangeProxy(): Proxy settings could not be changed.")
		return false, fmt.Errorf("%s", err.Error)
	}
}
