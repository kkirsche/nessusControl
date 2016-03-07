package nessusTransporter

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/kkirsche/go-scp"
)

// RetrieveResultFiles retrieves files from a remote path and copies them to the
// local machine
func (t *Transporter) RetrieveResultFiles(remoteResultsPath, localResultsPath string, removeFiles bool) error {
	if t.debug {
		fmt.Printf("Retrieving file listing from %s\n", remoteResultsPath)
	}

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
		if t.debug {
			fmt.Printf("Retrieving file with name %s\n", file)
		}

		err = goScp.CopyRemoteFileToLocal(t.Client, remoteResultsPath, file, localResultsPath, "")
		if err != nil {
			return err
		}

		remoteCommand := fmt.Sprintf("rm %s/%s", remoteResultsPath, file)
		_, err = goScp.ExecuteCommand(t.Client, remoteCommand)
		if err != nil {
			return err
		}
	}

	return nil
}
