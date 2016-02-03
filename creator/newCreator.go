package nessusCreator

import (
	"database/sql"
	"fmt"
	"github.com/kkirsche/nessusControl/api" // nessusAPI is not used
	"net/http"
	"os"
)

// NewCreator creates a new Nessus Creator object for use in creating an
// automated scan pipeline
func NewCreator(baseDirectory string, client *nessusAPI.Client, httpClient *http.Client, sqliteDB *sql.DB, debug bool) *Creator {
	return &Creator{
		apiClient:  client,
		debug:      debug,
		httpClient: httpClient,
		sqliteDB:   sqliteDB,
		fileLocations: fileLocations{
			baseDirectory:      baseDirectory,
			archiveDirectory:   fmt.Sprintf("%s/targets/archive", baseDirectory),
			temporaryDirectory: fmt.Sprintf("%s/targets/temp%d", baseDirectory, os.Getpid()),
			incomingDirectory:  fmt.Sprintf("%s/targets/incoming", baseDirectory),
		},
	}
}
