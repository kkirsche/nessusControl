package nessusImporter

import (
	"github.com/kkirsche/nessusControl/api" // nessusAPI is not used
)

// Importer is used in the file to scan pipeline to import the scan files,
// convert them into a form usable by Nessus, and then create and launch the scan.
type Importer struct {
	FileLocations
	APIClient *nessusAPI.Client
}

// FileLocations represents where files will be found on a system. Specifically
// we have the temporary directory where we store stuff while it is being processed,
// archive directory where we store processed files, incoming directory where
// target files are stored prior to being processed.
type FileLocations struct {
	BaseDirectory      string
	TemporaryDirectory string
	ArchiveDirectory   string
	IncomingDirectory  string
}
