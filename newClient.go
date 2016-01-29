package nessus

// NewUsernameClient creates a new Nessus API Client structure using a
// combination of username and password.
func NewUsernameClient(host, port, username, password string, debug bool) *Client {
	return &Client{
		ip:       host,
		port:     port,
		username: username,
		password: password,
		debug:    debug,
	}
}

// NewAccessTokenClient creates a new Nessus API Client structure using a
// combination of access key and secret key.
func NewAccessTokenClient(host, port, accessKey, secretKey string, debug bool) *Client {
	return &Client{
		ip:        host,
		port:      port,
		accessKey: accessKey,
		secretKey: secretKey,
		debug:     debug,
	}
}
