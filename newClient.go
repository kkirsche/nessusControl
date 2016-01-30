package nessus

// NewUsernameClient creates a new Nessus API Client structure using a
// combination of username and password. Please note you must call NewSession
// after creating a client to initialize the connection.
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
// combination of access key and secret key. Please note you must call NewSession
// after creating a client to initialize the connection.
func NewAccessTokenClient(host, port, accessKey, secretKey string, debug bool) *Client {
	return &Client{
		ip:        host,
		port:      port,
		accessKey: accessKey,
		secretKey: secretKey,
		debug:     debug,
	}
}
