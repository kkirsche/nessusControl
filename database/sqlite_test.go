package nessusDatabase

import (
	"os"
	"testing"
)

func TestConnectToSQLite(t *testing.T) {
	pwd, err := os.Getwd()
	if err != nil {
		t.FailNow()
	}

	db, err := ConnectToSQLite(pwd + "/test/fixtures/testDatabase.db")
	if err != nil {
		t.FailNow()
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		t.FailNow()
	}
}
