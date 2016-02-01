package nessus

// CreateSessionResponse is The response from Nessus when CreateSession() is called.
type CreateSessionResponse struct {
	Token string `json:"token"`
}

// SessionInfo represents the current user's session information
type SessionInfo struct {
	Connectors      interface{} `json:"connectors"`
	ContainerID     int         `json:"container_id"`
	Email           string      `json:"email"`
	Groups          interface{} `json:"groups"`
	ID              int         `json:"id"`
	Lastlogin       int         `json:"lastlogin"`
	Lockout         bool        `json:"lockout"`
	Name            string      `json:"name"`
	Permissions     int         `json:"permissions"`
	Type            string      `json:"type"`
	Username        string      `json:"username"`
	Whatsnew        bool        `json:"whatsnew"`
	WhatsnewVersion string      `json:"whatsnew_version"`
}

// NewAPIKeys is the response to GenerateAPIKeys which includes the new API keys
// to connect to the API.
type NewAPIKeys struct {
	AccessKey string `json:"accessKey"`
	SecretKey string `json:"secretKey"`
}
