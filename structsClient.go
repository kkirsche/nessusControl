package client

// Client is
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
