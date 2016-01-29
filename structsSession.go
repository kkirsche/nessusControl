package client

// The response from Nessus when CreateSession() is called.
type createSessionResponse struct {
	Token string `json:"token"`
}

type errorResponse struct {
	Error string `json:"error"`
}

type editSessionResponse struct {
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
