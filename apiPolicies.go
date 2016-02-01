package nessus

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// ExportPolicy exports the given policy in nessus (XML) format.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) ExportPolicy(httpClient *http.Client, policyID int) (string, error) {
	c.debugln("ListPolicy(): Building list policies URL")
	url := fmt.Sprintf("https://%s:%s/policies/%d/export", c.ip, c.port, policyID)

	statusCode, body, err := c.get(httpClient, url)
	if err != nil {
		return "", err
	}

	switch statusCode {
	case 200:
		c.debugln("ListPolicy(): Successfully retrieved policy list.")
		return string(body), nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return "", unmarshalError
		}
		c.debugln("ListPolicy(): Policy list could not be retrieved.")
		return "", fmt.Errorf("%s", err.Error)
	}
}

// ListPolicy returns the policy list.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) ListPolicy(httpClient *http.Client) (ListPolicyResponse, error) {
	c.debugln("ListPolicy(): Building list policies URL")
	url := fmt.Sprintf("https://%s:%s/policies", c.ip, c.port)

	statusCode, body, err := c.get(httpClient, url)
	if err != nil {
		return ListPolicyResponse{}, err
	}

	switch statusCode {
	case 200:
		var policies ListPolicyResponse
		err = json.Unmarshal(body, &policies)
		if err != nil {
			fmt.Println(err.Error())
			return ListPolicyResponse{}, err
		}
		c.debugln("ListPolicy(): Successfully retrieved policy list.")
		return policies, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return ListPolicyResponse{}, unmarshalError
		}
		c.debugln("ListPolicy(): Policy list could not be retrieved.")
		return ListPolicyResponse{}, fmt.Errorf("%s", err.Error)
	}
}
