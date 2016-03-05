package nessusExporter

import (
	"github.com/kkirsche/nessusControl/api"
	"github.com/kkirsche/nessusControl/database"
	"net/http"
	"os"
	"testing"
)

func TestNewCreator(t *testing.T) {
	debug := false
	client := nessusAPI.NewUsernameClient("localhost", "8834", "testU", "testP", debug)
	httpClient := &http.Client{}
	pwd, err := os.Getwd()
  if err != nil {
    t.FailNow()
  }
	db, err := nessusDatabase.ConnectToSQLite(pwd + "test/fixtures/testDatabase.db")
  if err != nil {
    t.FailNow()
  }
	fileLocations := fileLocations{}
	exporter := NewExporter(client, db, httpClient, fileLocations, debug)

	if exporter.debug != false ||
		exporter.apiClient != client ||
		exporter.sqliteDB != db ||
		exporter.httpClient != httpClient ||
		exporter.fileLocations != fileLocations {
		t.FailNow()
	}
}
