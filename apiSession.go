package client

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// CreateSession creates a new session token for the given user.
func (c *Client) CreateSession(httpClient *http.Client) (*Client, error) {
	c.debugln("CreateSession(): Creating new client with username and password")
	url := fmt.Sprintf("https://%s:%s/session", c.ip, c.port)
	jsonStr := []byte(fmt.Sprintf(`{"username":"%s","password":"%s"}`, c.username, c.password))
	c.debugln("CreateSession(): Creating HTTP request")

	body, err := c.postWithArgs(httpClient, url, jsonStr)
	if err != nil {
		return nil, err
	}

	var session createSession
	json.Unmarshal(body, &session)
	c.debugln("CreateSession(): Received token " + session.Token)
	c.token = session.Token
	return c, nil
}
