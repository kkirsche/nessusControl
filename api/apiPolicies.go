package nessusAPI

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// ConfigurePolicy changes the parameters of a policy.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) ConfigurePolicy(httpClient *http.Client, policyID int, configurationJSON string) (bool, error) {
	c.debugln("ConfigurePolicy(): Building policy configuration URL")
	url := fmt.Sprintf("https://%s:%s/policies/%d", c.ip, c.port, policyID)

	statusCode, body, err := c.putWithJSON(httpClient, url, []byte(configurationJSON))
	if err != nil {
		return false, err
	}

	switch statusCode {
	case 200:
		c.debugln("ConfigurePolicy(): Successfully configured the policy.")
		return true, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return false, unmarshalError
		}
		c.debugln("ConfigurePolicy(): Policy could not be configured.")
		return false, fmt.Errorf("%s", err.Error)
	}
}

// CopyPolicy copies a policy.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) CopyPolicy(httpClient *http.Client, policyID int) (CopyPolicyResponse, error) {
	c.debugln("CopyPolicy(): Building copy policy URL")
	url := fmt.Sprintf("https://%s:%s/policies/%d/copy", c.ip, c.port, policyID)

	statusCode, body, err := c.postWithJSON(httpClient, url, nil)
	if err != nil {
		return CopyPolicyResponse{}, err
	}

	switch statusCode {
	case 200:
		var policy CopyPolicyResponse
		err = json.Unmarshal(body, &policy)
		if err != nil {
			return CopyPolicyResponse{}, err
		}
		c.debugln("CopyPolicy(): Successfully copied the policy.")
		return policy, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return CopyPolicyResponse{}, unmarshalError
		}
		c.debugln("CopyPolicy(): Policy could not be copied.")
		return CopyPolicyResponse{}, fmt.Errorf("%s", err.Error)
	}
}

// CreatePolicy creates a policy.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) CreatePolicy(httpClient *http.Client, policyJSON string) (CreatePolicyResponse, error) {
	c.debugln("CreatePolicy(): Building create policy URL")
	url := fmt.Sprintf("https://%s:%s/policies", c.ip, c.port)

	statusCode, body, err := c.postWithJSON(httpClient, url, []byte(policyJSON))
	if err != nil {
		return CreatePolicyResponse{}, err
	}

	switch statusCode {
	case 200:
		var policy CreatePolicyResponse
		err = json.Unmarshal(body, &policy)
		if err != nil {
			return CreatePolicyResponse{}, err
		}
		c.debugln("CreatePolicy(): Successfully created policy.")
		return policy, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return CreatePolicyResponse{}, unmarshalError
		}
		c.debugln("CreatePolicy(): Policy could not be created.")
		return CreatePolicyResponse{}, fmt.Errorf("%s", err.Error)
	}
}

// DeletePolicy deletes a policy.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) DeletePolicy(httpClient *http.Client, policyID int) (bool, error) {
	c.debugln("DeletePolicy(): Building delete policy URL")
	url := fmt.Sprintf("https://%s:%s/policies/%d", c.ip, c.port, policyID)

	statusCode, body, err := c.delete(httpClient, url)
	if err != nil {
		return false, err
	}

	switch statusCode {
	case 200:
		c.debugln("DeletePolicy(): Successfully deleted the policy.")
		return true, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return false, unmarshalError
		}
		c.debugln("DeletePolicy(): Policy could not be deleted.")
		return false, fmt.Errorf("%s", err.Error)
	}
}

// PolicyDetails returns details for the given policy.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) PolicyDetails(httpClient *http.Client, policyID int) (PolicyDetailsResponse, error) {
	c.debugln("PolicyDetails(): Building policy details URL")
	url := fmt.Sprintf("https://%s:%s/policies/%d", c.ip, c.port, policyID)

	statusCode, body, err := c.get(httpClient, url)
	if err != nil {
		return PolicyDetailsResponse{}, err
	}

	switch statusCode {
	case 200:
		var policyDetails PolicyDetailsResponse
		err = json.Unmarshal(body, &policyDetails)
		if err != nil {
			return PolicyDetailsResponse{}, err
		}
		c.debugln("PolicyDetails(): Successfully retrieved policy details.")
		return policyDetails, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return PolicyDetailsResponse{}, unmarshalError
		}
		c.debugln("PolicyDetails(): Policy details could not be retrieved.")
		return PolicyDetailsResponse{}, fmt.Errorf("%s", err.Error)
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
