// Package nessusCreator uses Tenable's Nessus 6 API to automate scan creation via files.
//
// The Ingest Pipeline represents the method which should be used when interacting
// with this package. It will process each file within a given directory, generate
// a scan if it can, launch the scan, and then store the scan UUID for results
// processing.
package nessusCreator

import (
	"log"
)

// debugln is used to print a message out to the command line if the client's
// debug field is true.
func (c *Creator) debugln(message string) {
	if c.debug {
		log.Print(message)
	}
}
