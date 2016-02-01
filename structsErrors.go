package nessus

// ErrorResponse is used whenever there is an error with completing a request
// to Nessus
type ErrorResponse struct {
	Error string `json:"error"`
}
