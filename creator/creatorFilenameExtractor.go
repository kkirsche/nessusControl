package nessusCreator

import (
	"runtime"
	"strings"
)

func (c *Creator) filenameFromPath(filePath string) string {
	var splitPath []string
	if runtime.GOOS == "windows" {
		splitPath = strings.Split(filePath, "\\")
	} else {
		splitPath = strings.Split(filePath, "/")
	}

	fileName := splitPath[len(splitPath)-1] // ::: the filename from the path
	return fileName
}
