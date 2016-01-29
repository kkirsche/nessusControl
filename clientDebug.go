package client

import (
	"log"
)

// debugln is used to print a message out to the command line if the client's
// debug field is true.
func (c *Client) debugln(message string) {
	if c.debug {
		log.Print(message)
	}
}
