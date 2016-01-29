package client

// The response from Nessus when CreateSession() is called.
type createSessionResponse struct {
	Token string `json:"token"`
}

type errorResponse struct {
	Error string `json:"error"`
}
