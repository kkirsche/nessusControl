package nessusCreator

import (
	"log"
)

// IngestPipeline is used to run the creator's ingest pipeline
func (c *Creator) IngestPipeline() error {
	requestedScanCh, err := c.processRequestedScanDirectory(c.fileLocations.incomingDirectory)
	if err != nil {
		return err
	}
	createScanJSONCh := c.buildCreateScanJSON(requestedScanCh)
	createdScanCh := c.createScan(createScanJSONCh)
	launchedScanCh := c.launchScan(createdScanCh)

	for launchedScan := range launchedScanCh {
		log.Println(launchedScan.ScanUUID)
	}
	return nil
}
