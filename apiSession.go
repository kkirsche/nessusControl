package client

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// CreateSession creates a new session token for the given user/password within
// Client. It requires an http.Client pointer to make the request to Nessus.
func (c *Client) CreateSession(httpClient *http.Client) (*Client, error) {
	c.debugln("CreateSession(): Creating new client with username and password")
	url := fmt.Sprintf("https://%s:%s/session", c.ip, c.port)
	jsonStr := []byte(fmt.Sprintf(`{"username":"%s","password":"%s"}`, c.username, c.password))
	c.debugln("CreateSession(): Creating HTTP request")

	statusCode, body, err := c.postWithJSON(httpClient, url, jsonStr)
	if err != nil {
		return nil, err
	}

	switch statusCode {
	case 200:
		var session createSessionResponse
		json.Unmarshal(body, &session)
		c.debugln("CreateSession(): Received token " + session.Token)
		c.token = session.Token
		return c, nil
	default:
		var err errorResponse
		json.Unmarshal(body, &err)
		c.debugln("CreateSession(): Session could not be created.")
		return nil, fmt.Errorf("%s", err.Error)
	}
}

// DestroySession logs the current user out and destroys the session.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) DestroySession(httpClient *http.Client) (bool, error) {
	c.debugln("DestroySession(): Creating new client with username and password")
	url := fmt.Sprintf("https://%s:%s/session", c.ip, c.port)

	c.debugln("DestroySession(): Creating HTTP request")
	statusCode, body, err := c.delete(httpClient, url)
	if err != nil {
		return false, err
	}

	switch statusCode {
	case 200:
		c.debugln("DestroySession(): Session destroyed.")
		return true, nil
	default:
		var err errorResponse
		json.Unmarshal(body, &err)
		c.debugln("DestroySession(): Session could not be destroyed.")
		return false, fmt.Errorf("%s", err.Error)
	}
}
