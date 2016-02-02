package nessusAPI

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// DeleteAgent deletes an agent.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) DeleteAgent(httpClient *http.Client, scannerID, agentID int) (bool, error) {
	c.debugln("DeleteAgent(): Building delete agent URL")
	url := fmt.Sprintf("https://%s:%s/scanners/%d/agents/%d", c.ip, c.port, scannerID, agentID)

	statusCode, body, err := c.delete(httpClient, url)
	if err != nil {
		return false, err
	}

	switch statusCode {
	case 200:
		c.debugln("DeleteAgent(): Successfully deleted agent.")
		return true, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return false, unmarshalError
		}
		c.debugln("DeleteAgent(): Agent could not be deleted.")
		return false, fmt.Errorf("%s", err.Error)
	}
}

// ListAgents returns the agent list for the given scanner.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) ListAgents(httpClient *http.Client, scannerID int) (Agents, error) {
	c.debugln("ListAgents(): Building list agents URL")
	url := fmt.Sprintf("https://%s:%s/scanners/%d/agents", c.ip, c.port, scannerID)

	statusCode, body, err := c.get(httpClient, url)
	if err != nil {
		return Agents{}, err
	}

	switch statusCode {
	case 200:
		var agentsList Agents
		err = json.Unmarshal(body, &agentsList)
		if err != nil {
			return Agents{}, err
		}
		c.debugln("ListAgents(): Successfully retrieved list of agents.")
		return agentsList, nil
	default:
		var err ErrorResponse
		unmarshalError := json.Unmarshal(body, &err)
		if unmarshalError != nil {
			return Agents{}, unmarshalError
		}
		c.debugln("ListAgents(): Agents list could not be retrieved.")
		return Agents{}, fmt.Errorf("%s", err.Error)
	}
}
