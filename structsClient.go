package nessus

// Client represents the API client which is used to interact with the
// Nessus API. It supports either Username/Password or Access/Secret key pairs.
type Client struct {
	ip    string
	port  string
	debug bool

	username string
	password string
	token    string

	accessKey string
	secretKey string
}
