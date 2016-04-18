package nessusExporter

import (
	"database/sql"
	"net/http"

	"github.com/kkirsche/nessusControl/api"
)

// Exporter is used to retrieve
type Exporter struct {
	apiClient     *nessusAPI.Client
	sqliteDB      *sql.DB
	httpClient    *http.Client
	fileLocations FileLocations
	debug         bool
}

// FileLocations represents where files should be held
type FileLocations struct {
	baseDirectory    string
	resultsDirectory string
}
