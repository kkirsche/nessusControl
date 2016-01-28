package client

import (
	"log"
)

func (c *Client) debugln(message string) {
	if c.debug {
		log.Print(message)
	}
}
