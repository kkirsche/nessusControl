package nessusExporter

import (
	"database/sql"
	"github.com/kkirsche/nessusControl/api"
	"net/http"
)

// NewExporter returns a new exporter instance for use in exporting scan results
func NewExporter(apiClient *nessusAPI.Client, httpClient *http.Client, sqliteDB *sql.DB, fileLocations fileLocations, debug bool) *Exporter {
	return &Exporter{
		apiClient:     apiClient,
		sqliteDB:      sqliteDB,
		httpClient:    httpClient,
		fileLocations: fileLocations,
		debug:         debug,
	}
}

// NewFileLocations returns a new fileLocations struct for use in an exporter.
func NewFileLocations(baseDirectory, pathToResultsFromBase string) fileLocations {
	return fileLocations{
		baseDirectory:    baseDirectory,
		resultsDirectory: baseDirectory + pathToResultsFromBase,
	}
}
