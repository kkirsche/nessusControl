package nessusAPI

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// ChangeMailSettings changes the permissions for an object. Allowed objectType
// values are "policy", "scan", "scanner", "agent-group", "scanner-pool", and
// "connector".
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) ChangeMailSettings(httpClient *http.Client, updatedMailSettings string) (bool, error) {
	c.debugln("ChangeMailSettings(): Building change mail settings URL")
	url := fmt.Sprintf("https://%s:%s/settings/network/mail", c.ip, c.port)

	statusCode, body, err := c.putWithJSON(httpClient, url, []byte(updatedMailSettings))
	if err != nil {
		return false, err
	}

	switch statusCode {
	case 200:
		c.debugln("ChangeMailSettings(): Successfully changed mail settings.")
		return true, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return false, unmarshalError
		}
		c.debugln("ChangeMailSettings(): Mail settings could not be changed.")
		return false, fmt.Errorf("%s", err.Error)
	}
}

// ViewMailSettings returns the mail server settings.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) ViewMailSettings(httpClient *http.Client) (MailSettings, error) {
	c.debugln("ViewMailSettings(): Building view mail settings URL")
	url := fmt.Sprintf("https://%s:%s/settings/network/mail", c.ip, c.port)

	statusCode, body, err := c.get(httpClient, url)
	if err != nil {
		return MailSettings{}, err
	}

	switch statusCode {
	case 200:
		var mailSettings MailSettings
		err = json.Unmarshal(body, &mailSettings)
		if err != nil {
			return MailSettings{}, err
		}
		c.debugln("ViewMailSettings(): Successfully retrieved mail settings.")
		return mailSettings, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return MailSettings{}, unmarshalError
		}
		c.debugln("ViewMailSettings(): Mail settings could not be retrieved.")
		return MailSettings{}, fmt.Errorf("%s", err.Error)
	}
}
