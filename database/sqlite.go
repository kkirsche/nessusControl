package nessusDatabase

import (
	"database/sql"
	"fmt"
	// We need to load the driver even though we don't use it explicitly
	_ "github.com/mattn/go-sqlite3"
)

// ConnectToSQLite generates a file connection to an SQLite3 database.
func ConnectToSQLite(SQLiteDBName string) (*sql.DB, error) {
	file := fmt.Sprintf("file:%s", SQLiteDBName)
	db, err := sql.Open("sqlite3", file)
	if err != nil {
		return nil, err
	}
	return db, nil
}
