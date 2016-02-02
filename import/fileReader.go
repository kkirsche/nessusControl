package nessusImporter

import (
	"encoding/json"
	"encoding/xml"
	"io/ioutil"
)

func (i *Importer) readJSON(jsonFilePath string) (RequestedScan, error) {
	fileContents, err := ioutil.ReadFile(jsonFilePath)

	var requestedScan RequestedScan
	err = json.Unmarshal(fileContents, &requestedScan)
	if err != nil {
		return RequestedScan{}, nil
	}

	return requestedScan, nil
}

func (i *Importer) readXML(xmlFilePath string) (RequestedScan, error) {
	fileContents, err := ioutil.ReadFile(xmlFilePath)

	var requestedScan RequestedScan
	err = xml.Unmarshal(fileContents, &requestedScan)
	if err != nil {
		return RequestedScan{}, nil
	}

	return requestedScan, nil
}
