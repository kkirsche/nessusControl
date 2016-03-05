package nessusExporter

import (
	"database/sql"
	"github.com/kkirsche/nessusControl/api"
	"net/http"
)

// NewExporter returns a new exporter instance for use in exporting scan results
func NewExporter(apiClient *nessusAPI.Client, sqliteDB *sql.DB, httpClient *http.Client, fileLocations fileLocations, debug bool) *Exporter {
	return &Exporter{
		apiClient:     apiClient,
		sqliteDB:      sqliteDB,
		httpClient:    httpClient,
		fileLocations: fileLocations,
		debug:         debug,
	}
}
