package nessusCreator

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
)

func (c *Creator) readJSON(jsonFilePath string) (RequestedScan, error) {
	c.debugln("readJSON(): Reading JSON file into memory")
	fileContents, err := ioutil.ReadFile(jsonFilePath)

	c.debugln("readJSON(): Unmarshalling JSON file into structure")
	var requestedScan RequestedScan
	err = json.Unmarshal(fileContents, &requestedScan)
	if err != nil {
		c.debugln("readJSON(): Failed to unmarshal JSON")
		return RequestedScan{}, nil
	}

	c.debugln("readJSON(): Successfully unmarshalled JSON file")
	return requestedScan, nil
}

func (c *Creator) readXML(xmlFilePath string) (RequestedScan, error) {
	c.debugln("readXML(): Reading XML file into memory")
	fileContents, err := ioutil.ReadFile(xmlFilePath)

	c.debugln("readXML(): Unmarshalling XML file into structure")
	var requestedScan RequestedScan
	err = xml.Unmarshal(fileContents, &requestedScan)
	if err != nil {
		c.debugln("readJSON(): Failed to unmarshal XML")
		return RequestedScan{}, nil
	}

	c.debugln("readJSON(): Successfully unmarshalled XML file")
	return requestedScan, nil
}

func (c *Creator) readText(textFilePath string) (RequestedScan, error) {
	c.debugln("readText(): Opening file")
	file, err := os.Open(textFilePath)
	if err != nil {
		return RequestedScan{}, err
	}
	defer file.Close()

	c.debugln("readText(): Creating file scanner")
	scanner := bufio.NewScanner(file)
	var requestID string
	var method string
	var IPs []string
	for scanner.Scan() {
		lineType, lineValue, err := c.processTextFileLine(scanner.Text())
		if err != nil {
			return RequestedScan{}, err
		}
		switch lineType {
		case "requestID":
			c.debugln("readText(): Found request ID line")
			requestID = lineValue
		case "method":
			c.debugln("readText(): Found method line")
			method = lineValue
		case "ip":
			c.debugln("readText(): Found IP line")
			IPs = append(IPs, lineValue)
		}
	}

	if err := scanner.Err(); err != nil {
		c.debugln("readText(): Error occurred while scanning text file")
		return RequestedScan{}, err
	}

	c.debugln("readText(): Scan request completed")
	return RequestedScan{
		RequestID: requestID,
		Method:    method,
		TargetIPs: IPs,
	}, nil
}

func (c *Creator) processTextFileLine(line string) (string, string, error) {
	c.debugln("processTextFileLine(): Creating capture regular expression")
	captureRegexp := regexp.MustCompile(`(?P<requestid>requestid:\s*|requestid:\t)?(?P<method>method:\t|method:\s*)?(?P<result>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d+|\d+|\w+)`)

	match := captureRegexp.FindStringSubmatch(line)
	result := make(map[string]string)
	c.debugln("processTextFileLine(): Looking for matching substring(s)")
	for i, name := range captureRegexp.SubexpNames() {
		if i != 0 {
			result[name] = match[i]
		}
	}

	resultID := regexp.MustCompile(`(\d+)`)
	result["extractedRequestId"] = resultID.FindString(result["result"])

	method := regexp.MustCompile(`(\w+)`)
	result["extractedMethod"] = method.FindString(result["result"])

	ipRegexp := regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d+`)
	result["ips"] = ipRegexp.FindString(result["result"])

	if result["extractedRequestId"] != "" && result["requestid"] != "" &&
		result["method"] == "" {
		c.debugln("processTextFileLine(): Request ID substring found")
		return "requestID", result["extractedRequestId"], nil
	}

	if result["extractedMethod"] != "" && result["method"] != "" &&
		result["requestid"] == "" {
		c.debugln("processTextFileLine(): Method substring found")
		return "method", result["extractedMethod"], nil
	}

	if result["ips"] != "" {
		c.debugln("processTextFileLine(): IP substring found")
		return "ip", result["ips"], nil
	}

	c.debugln("processTextFileLine(): No matching substring(s) found")
	return "", "", fmt.Errorf("Line was not a request ID, method, or IP/CIDR block.")
}
