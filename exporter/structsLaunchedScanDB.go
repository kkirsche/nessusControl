package nessusExporter

// launchedScanDBRow represents a single row in the SQLite3 database. It represents
// a single scan which was launched
type launchedScanDBRow struct {
	requestID     int
	method        string
	scanUUID      string
	scanID        int
	scanStartTime string
}
