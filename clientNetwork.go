package client

import (
	"bytes"
	"io/ioutil"
	"net/http"
)

func (c *Client) postWithArgs(httpClient *http.Client, url string, jsonStr []byte) ([]byte, error) {
	c.debugln("postWithArgs(): Creating new request")
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	c.debugln("postWithArgs(): Executing request")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	c.debugln("postWithArgs(): Reading body of response")
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}
