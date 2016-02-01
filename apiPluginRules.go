package nessus

import (
	"encoding/json"
	"fmt"
	"net/http"
)

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
