package nessus

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// PolicyDetails returns details for the given policy.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) PolicyDetails(httpClient *http.Client, policyID int) (PolicyDetails, error) {
	c.debugln("ImportPolicy(): Building import policy URL")
	url := fmt.Sprintf("https://%s:%s/policies/%d", c.ip, c.port, policyID)

	statusCode, body, err := c.get(httpClient, url)
	if err != nil {
		return PolicyDetails{}, err
	}

	switch statusCode {
	case 200:
		var policyDetails PolicyDetails
		err = json.Unmarshal(body, &policyDetails)
		if err != nil {
			return PolicyDetails{}, err
		}
		c.debugln("ImportPolicy(): Successfully imported policy file.")
		return policyDetails, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return PolicyDetails{}, unmarshalError
		}
		c.debugln("ImportPolicy(): Policy file could not be imported.")
		return PolicyDetails{}, fmt.Errorf("%s", err.Error)
	}
}

// ImportPolicy imports an existing policy uploaded using Nessus.file
// (.nessus format only).
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) ImportPolicy(httpClient *http.Client, file string) (PolicyResponse, error) {
	c.debugln("ImportPolicy(): Building import policy URL")
	url := fmt.Sprintf("https://%s:%s/policies/import", c.ip, c.port)
	fileString := fmt.Sprintf(`{"file":"%s"}`, file)
	fileJSON, err := json.Marshal(fileString)
	if err != nil {
		return PolicyResponse{}, err
	}

	statusCode, body, err := c.postWithJSON(httpClient, url, fileJSON)
	if err != nil {
		return PolicyResponse{}, err
	}

	switch statusCode {
	case 200:
		var policy PolicyResponse
		err = json.Unmarshal(body, &policy)
		if err != nil {
			return PolicyResponse{}, err
		}
		c.debugln("ImportPolicy(): Successfully imported policy file.")
		return policy, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return PolicyResponse{}, unmarshalError
		}
		c.debugln("ImportPolicy(): Policy file could not be imported.")
		return PolicyResponse{}, fmt.Errorf("%s", err.Error)
	}
}

// ExportPolicy exports the given policy in nessus (XML) format.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) ExportPolicy(httpClient *http.Client, policyID int) (string, error) {
	c.debugln("ExportPolicy(): Building export policy URL")
	url := fmt.Sprintf("https://%s:%s/policies/%d/export", c.ip, c.port, policyID)

	statusCode, body, err := c.get(httpClient, url)
	if err != nil {
		return "", err
	}

	switch statusCode {
	case 200:
		c.debugln("ListPolicy(): Successfully exported policy.")
		return string(body), nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return "", unmarshalError
		}
		c.debugln("ExportPolicy(): Policy could not be exported.")
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
