package nessusCreator

// IngestPipeline is used to run the creator's ingest pipeline. The ingest
// pipeline will take all the files in the creator's file location's incoming
// directory, process them for valid .json, .xml, or .txt requested scan files
// , create a scan within Nessus, and then launch the scan.
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
	err = c.saveLaunchedScan(launchedScanCh)
	if err != nil {
		return err
	}
	return nil
}
