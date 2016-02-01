package nessus

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// CreateSession creates a new session token for the given user/password within
// Client. It requires an http.Client pointer to make the request to Nessus.
func (c *Client) CreateSession(httpClient *http.Client) (*Client, error) {
	c.debugln("CreateSession(): Building create session URL")
	url := fmt.Sprintf("https://%s:%s/session", c.ip, c.port)
	jsonStr := []byte(fmt.Sprintf(`{"username":"%s","password":"%s"}`, c.username, c.password))

	statusCode, body, err := c.postWithJSON(httpClient, url, jsonStr)
	if err != nil {
		return nil, err
	}

	switch statusCode {
	case 200:
		var session CreateSessionResponse
		err := json.Unmarshal(body, &session)
		if err != nil {
			return nil, err
		}
		c.debugln("CreateSession(): Received token " + session.Token)
		c.token = session.Token
		return c, nil
	default:
		var err ErrorResponse
		unmarErr := json.Unmarshal(body, &err)
		if unmarErr != nil {
			return nil, unmarErr
		}
		c.debugln("CreateSession(): Session could not be created.")
		return nil, fmt.Errorf("%s", err.Error)
	}
}

// DestroySession logs the current user out and destroys the session.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) DestroySession(httpClient *http.Client) (bool, error) {
	c.debugln("DestroySession(): Building destroy session URL")
	url := fmt.Sprintf("https://%s:%s/session", c.ip, c.port)

	statusCode, body, err := c.delete(httpClient, url)
	if err != nil {
		return false, err
	}

	switch statusCode {
	case 200:
		c.debugln("DestroySession(): Session destroyed.")
		return true, nil
	default:
		var err ErrorResponse
		json.Unmarshal(body, &err)
		c.debugln("DestroySession(): Session could not be destroyed.")
		return false, fmt.Errorf("%s", err.Error)
	}
}

// EditSession changes settings for the current user.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) EditSession(httpClient *http.Client, updateJSON string) (SessionInfo, error) {
	c.debugln("EditSession(): Building edit session URL")
	url := fmt.Sprintf("https://%s:%s/session", c.ip, c.port)

	statusCode, body, err := c.putWithJSON(httpClient, url, []byte(updateJSON))
	if err != nil {
		return SessionInfo{}, err
	}

	switch statusCode {
	case 200:
		var session SessionInfo
		err := json.Unmarshal(body, &session)
		if err != nil {
			return SessionInfo{}, err
		}
		c.debugln("EditSession(): Successfully update session.")
		return session, nil
	default:
		var err ErrorResponse
		unmarErr := json.Unmarshal(body, &err)
		if unmarErr != nil {
			return SessionInfo{}, unmarErr
		}
		c.debugln("EditSession(): Session could not be created.")
		return SessionInfo{}, fmt.Errorf("%s", err.Error)
	}
}

// GetSession returns the user session data.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) GetSession(httpClient *http.Client) (SessionInfo, error) {
	c.debugln("GetSession(): Building get session URL")
	url := fmt.Sprintf("https://%s:%s/session", c.ip, c.port)

	statusCode, body, err := c.get(httpClient, url)
	if err != nil {
		return SessionInfo{}, err
	}

	switch statusCode {
	case 200:
		var session SessionInfo
		err := json.Unmarshal(body, &session)
		if err != nil {
			return SessionInfo{}, err
		}
		c.debugln("GetSession(): Successfully retrieved session.")
		return session, nil
	default:
		var err ErrorResponse
		unmarErr := json.Unmarshal(body, &err)
		if unmarErr != nil {
			return SessionInfo{}, unmarErr
		}
		c.debugln("EditSession(): Session could not be retrieved.")
		return SessionInfo{}, fmt.Errorf("%s", err.Error)
	}
}

// ChangePassword changes password for the current user.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) ChangePassword(httpClient *http.Client, newPassword string) (bool, error) {
	c.debugln("ChangePassword(): Building change password URL")
	url := fmt.Sprintf("https://%s:%s/session/chpasswd", c.ip, c.port)

	newPasswordJSON := []byte(fmt.Sprintf(`{"password":"%s"}`, newPassword))

	statusCode, body, err := c.putWithJSON(httpClient, url, []byte(newPasswordJSON))
	if err != nil {
		return false, err
	}

	switch statusCode {
	case 200:
		c.debugln("ChangePassword(): Successfully changed password.")
		return true, nil
	default:
		var err ErrorResponse
		unmarErr := json.Unmarshal(body, &err)
		if unmarErr != nil {
			return false, unmarErr
		}
		c.debugln("ChangePassword(): Password could not be changed.")
		return false, fmt.Errorf("%s", err.Error)
	}
}

// GenerateAPIKeys generates API Keys for the current user.
// It requires an http.Client pointer to make the request to Nessus.
func (c *Client) GenerateAPIKeys(httpClient *http.Client) (NewAPIKeys, error) {
	c.debugln("GenerateAPIKeys(): Building generate API Keys URL")
	url := fmt.Sprintf("https://%s:%s/session/keys", c.ip, c.port)

	statusCode, body, err := c.put(httpClient, url)
	if err != nil {
		return NewAPIKeys{}, err
	}

	switch statusCode {
	case 200:
		var apiKeys NewAPIKeys
		err := json.Unmarshal(body, &apiKeys)
		if err != nil {
			return NewAPIKeys{}, err
		}
		c.debugln("ChangePassword(): Successfully generated API keys.")
		return apiKeys, nil
	default:
		var err ErrorResponse
		unmarErr := json.Unmarshal(body, &err)
		if unmarErr != nil {
			return NewAPIKeys{}, unmarErr
		}
		c.debugln("ChangePassword(): API Keys could not be generated.")
		return NewAPIKeys{}, fmt.Errorf("%s", err.Error)
	}
}
