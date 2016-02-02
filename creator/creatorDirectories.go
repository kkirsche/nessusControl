package nessusCreator

import (
	"os"
)

func (c *Creator) removeTempDirIfEmpty() {
	isEmpty, err := isDirEmpty(c.fileLocations.temporaryDirectory)
	if err != nil {
		return
	}
	if isEmpty {
		os.Remove(c.fileLocations.temporaryDirectory)
	}
}

func (c *Creator) createNecessaryDirectories() error {
	c.debugln("createNecessaryDirectories(): Creating archive directory if it does not exist.")
	err := os.MkdirAll(c.fileLocations.archiveDirectory, 0755)
	if err != nil {
		return err
	}

	c.debugln("createNecessaryDirectories(): Creating incoming directory if it does not exist.")
	err = os.MkdirAll(c.fileLocations.incomingDirectory, 0755)
	if err != nil {
		return err
	}

	c.debugln("createNecessaryDirectories(): Creating temporary directory if it does not exist.")
	err = os.MkdirAll(c.fileLocations.temporaryDirectory, 0755)
	if err != nil {
		return err
	}

	return nil
}
