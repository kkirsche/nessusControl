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
		json.Unmarshal(body, &proxySettings)
		c.debugln("ViewProxy(): Successfully retrieved proxy settings.")
		return proxySettings, nil
	default:
		var err ErrorResponse
		json.Unmarshal(body, &err)
		c.debugln("ViewProxy(): Proxy settings could not be retrieved.")
		return ViewProxyResponse{}, fmt.Errorf("%s", err.Error)
	}
}
