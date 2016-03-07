package nessusTransporter

import (
	"regexp"
	"strings"

	"github.com/kkirsche/go-scp"
)

// RetrieveResultFiles retrieves files from a remote path and copies them to the
// local machine
func (t *Transporter) RetrieveResultFiles(remoteResultsPath, localResultsPath string) error {
	resultFiles, err := goScp.ExecuteCommand(t.Client, "ls -1 "+remoteResultsPath)
	if err != nil {
		return err
	}

	filenameSlice := strings.Split(resultFiles, "\n")

	var matches []string
	for _, file := range filenameSlice {
		match, err := regexp.MatchString(".+.csv", file)
		if err != nil {
			return err
		}

		if match {
			matches = append(matches, file)
		}
	}

	for _, file := range matches {
		err = goScp.CopyRemoteFileToLocal(t.Client, remoteResultsPath, file, localResultsPath, "")
		if err != nil {
			return err
		}
	}
	return nil
}
