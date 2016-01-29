package client

// The response from Nessus when CreateSession() is called.
type createSession struct {
	Token string `json:"token"`
}
