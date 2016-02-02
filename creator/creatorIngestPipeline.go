package nessusCreator

import (
// "fmt"
)

// IngestPipeline is used to run the creator's ingest pipeline
func (c *Creator) IngestPipeline(moveFiles bool) error {
	err := c.createNecessaryDirectories()
	defer c.removeTempDirIfEmpty()
	requestedScanCh, err := c.processRequestedScanDirectory(c.fileLocations.incomingDirectory, moveFiles)
	if err != nil {
		return err
	}
	createScanJSONCh := c.buildCreateScanJSON(requestedScanCh)
	createdScanCh := c.createScan(createScanJSONCh)
	launchedScanCh := c.launchScan(createdScanCh)

	if len(launchedScanCh) == 0 {
		// 	return fmt.Errorf("No scans were launched.")
	}
	return nil
}
