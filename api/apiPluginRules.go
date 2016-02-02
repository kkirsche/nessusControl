package nessusAPI

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// CreatePluginRule creates a new plugin rule for the current user.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) CreatePluginRule(httpClient *http.Client, pluginRuleJSON string) (bool, error) {
	c.debugln("CreatePluginRule(): Building create plugin rule URL")
	url := fmt.Sprintf("https://%s:%s/plugin-rules", c.ip, c.port)

	statusCode, body, err := c.postWithJSON(httpClient, url, []byte(pluginRuleJSON))
	if err != nil {
		return false, err
	}

	switch statusCode {
	case 200:
		c.debugln("CreatePluginRule(): Successfully created plugin rule.")
		return true, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return false, unmarshalError
		}
		c.debugln("CreatePluginRule(): Plugin rule could not be created.")
		return false, fmt.Errorf("%s", err.Error)
	}
}

// DeletePluginRule deletes a plugin rule.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) DeletePluginRule(httpClient *http.Client, ruleID int) (bool, error) {
	c.debugln("DeletePluginRule(): Building delete plugin rule URL")
	url := fmt.Sprintf("https://%s:%s/plugin-rules/%d", c.ip, c.port, ruleID)

	statusCode, body, err := c.delete(httpClient, url)
	if err != nil {
		return false, err
	}

	switch statusCode {
	case 200:
		c.debugln("DeletePluginRule(): Successfully deleted plugin rule.")
		return true, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return false, unmarshalError
		}
		c.debugln("DeletePluginRule(): Plugin rule could not be deleted.")
		return false, fmt.Errorf("%s", err.Error)
	}
}

// EditPluginRule modifies a plugin rule for the current user.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) EditPluginRule(httpClient *http.Client, ruleID int, editJSON string) (bool, error) {
	c.debugln("EditPluginRule(): Building edit plugin rule URL")
	url := fmt.Sprintf("https://%s:%s/plugin-rules/%d", c.ip, c.port, ruleID)

	statusCode, body, err := c.putWithJSON(httpClient, url, []byte(editJSON))
	if err != nil {
		return false, err
	}

	switch statusCode {
	case 200:
		c.debugln("EditPluginRule(): Successfully edited plugin rule.")
		return true, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return false, unmarshalError
		}
		c.debugln("EditPluginRule(): Plugin rule could not be edited.")
		return false, fmt.Errorf("%s", err.Error)
	}
}

// PluginRulesList returns the current user plugin rules.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) PluginRulesList(httpClient *http.Client) (PluginRulesList, error) {
	c.debugln("PluginRulesList(): Building plugin rule list URL")
	url := fmt.Sprintf("https://%s:%s/plugin-rules", c.ip, c.port)

	statusCode, body, err := c.get(httpClient, url)
	if err != nil {
		return PluginRulesList{}, err
	}

	switch statusCode {
	case 200:
		var rules PluginRulesList
		err = json.Unmarshal(body, &rules)
		if err != nil {
			return PluginRulesList{}, err
		}
		c.debugln("PluginRulesList(): Successfully retrieved plugin rule list.")
		return rules, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return PluginRulesList{}, unmarshalError
		}
		c.debugln("PluginRulesList(): Plugin rule list could not be retrieved.")
		return PluginRulesList{}, fmt.Errorf("%s", err.Error)
	}
}

// PluginRulesDetails returns the details for a given rule.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) PluginRulesDetails(httpClient *http.Client, ruleID int) (PluginRuleResponse, error) {
	c.debugln("PluginRulesDetails(): Building plugin rule details URL")
	url := fmt.Sprintf("https://%s:%s/plugin-rules/%d", c.ip, c.port, ruleID)

	statusCode, body, err := c.get(httpClient, url)
	if err != nil {
		return PluginRuleResponse{}, err
	}

	switch statusCode {
	case 200:
		var rule PluginRuleResponse
		err = json.Unmarshal(body, &rule)
		if err != nil {
			return PluginRuleResponse{}, err
		}
		c.debugln("PluginRulesDetails(): Successfully retrieved plugin rule details.")
		return rule, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return PluginRuleResponse{}, unmarshalError
		}
		c.debugln("PluginRulesDetails(): Plugin rule details could not be retrieved.")
		return PluginRuleResponse{}, fmt.Errorf("%s", err.Error)
	}
}
