package nessusCreator

import (
	"database/sql"
	"github.com/kkirsche/nessusControl/api" // nessusAPI is not used
	"net/http"
)

// Creator is used in the file to scan pipeline to import the scan files,
// convert them into a form usable by Nessus, and then create and launch the scan.
type Creator struct {
	fileLocations fileLocations
	apiClient     *nessusAPI.Client
	httpClient    *http.Client
	sqliteDB      *sql.DB
	debug         bool
}

// FileLocations represents where files will be found on a system. Specifically
// we have the temporary directory where we store stuff while it is being processed,
// archive directory where we store processed files, incoming directory where
// target files are stored prior to being processed.
type fileLocations struct {
	baseDirectory      string
	temporaryDirectory string
	archiveDirectory   string
	incomingDirectory  string
}
