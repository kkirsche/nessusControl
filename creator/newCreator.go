package nessusCreator

import (
	"fmt"
	"github.com/kkirsche/nessusControl/api" // nessusAPI is not used
	"os"
)

// NewCreator creates a new Nessus Creator object for use in creating an
// automated scan pipeline
func NewCreator(baseDirectory string, client *nessusAPI.Client, debug bool) *Creator {
	return &Creator{
		apiClient: client,
		debug:     debug,
		fileLocations: fileLocations{
			baseDirectory:      baseDirectory,
			archiveDirectory:   fmt.Sprintf("%s/targets/archive", baseDirectory),
			temporaryDirectory: fmt.Sprintf("%s/targets/temp%d", baseDirectory, os.Getpid()),
			incomingDirectory:  fmt.Sprintf("%s/targets/incoming", baseDirectory),
		},
	}
}
