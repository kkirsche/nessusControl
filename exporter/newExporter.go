package nessusExporter

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/kkirsche/nessusControl/api"
)

// NewExporter returns a new exporter instance for use in exporting scan results
func NewExporter(apiClient *nessusAPI.Client, httpClient *http.Client, sqliteDB *sql.DB, baseDirectory string, debug bool) *Exporter {
	return &Exporter{
		apiClient:     apiClient,
		sqliteDB:      sqliteDB,
		httpClient:    httpClient,
		fileLocations: NewFileLocations(baseDirectory),
		debug:         debug,
	}
}

// NewFileLocations returns a new fileLocations struct for use in an exporter.
func NewFileLocations(baseDirectory string) FileLocations {
	return FileLocations{
		baseDirectory:    baseDirectory,
		resultsDirectory: fmt.Sprintf("%s/results", baseDirectory),
	}
}
