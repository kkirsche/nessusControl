package nessusExporter

import (
	"database/sql"
	"github.com/kkirsche/nessusControl/api"
	"net/http"
)

// Exporter is used to retrieve
type Exporter struct {
	apiClient     *nessusAPI.Client
	sqliteDB      *sql.DB
	httpClient    *http.Client
	fileLocations fileLocations
	debug         bool
}

type fileLocations struct {
	baseDirectory    string
	resultsDirectory string
}
