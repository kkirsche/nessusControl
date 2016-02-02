package nessusCreator

import (
	"runtime"
	"strings"
)

func filename(path string) string {
	var splitPath []string
	if runtime.GOOS == "windows" {
		splitPath = strings.Split(path, "\\")
	} else {
		splitPath = strings.Split(path, "/")
	}

	return splitPath[len(splitPath)-1] // ::: the filename from the path
}
