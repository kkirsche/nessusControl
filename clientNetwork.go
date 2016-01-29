package client

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
)

// delete take an http.Client pointer and URL and sends a DELETE request to the
// server.
func (c *Client) delete(httpClient *http.Client, url string) (int, []byte, error) {
	c.debugln("delete(): Creating new request")
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return 0, nil, err
	}

	if c.token != "" {
		req.Header.Set("X-Cookie", "token="+c.token)
	}

	if c.accessKey != "" && c.secretKey != "" {
		header := fmt.Sprintf("accessKey=%s; secretKey=%s;", c.accessKey, c.secretKey)
		req.Header.Set("X-ApiKeys", header)
	}

	c.debugln("delete(): Executing request")
	resp, err := httpClient.Do(req)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	defer resp.Body.Close()

	c.debugln("delete(): Reading body of response")
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}

	return resp.StatusCode, body, err
}

// postWithArgs takes an http.Client pointer, URL, and JSON byte array,
// sends a POST request to the server, and then returns the response body as a
// byte array with a nil error. Otherwise, the array will be nil and an error
// will be passed
func (c *Client) postWithJSON(httpClient *http.Client, url string, jsonStr []byte) (int, []byte, error) {
	c.debugln("postWithJSON(): Creating new request")
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	if c.token != "" {
		req.Header.Set("X-Cookie", "token="+c.token)
	}

	if c.accessKey != "" && c.secretKey != "" {
		header := fmt.Sprintf("accessKey=%s; secretKey=%s;", c.accessKey, c.secretKey)
		req.Header.Set("X-ApiKeys", header)
	}

	c.debugln("postWithJSON(): Executing request")
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	c.debugln("postWithJSON(): Reading body of response")
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}

	return resp.StatusCode, body, nil
}

// postWithArgs takes an http.Client pointer, URL, and JSON byte array,
// sends a PUT request to the server, and then returns the response body as a
// byte array with a nil error. Otherwise, the array will be nil and an error
// will be passed
func (c *Client) putWithJSON(httpClient *http.Client, url string, jsonStr []byte) (int, []byte, error) {
	c.debugln("putWithJSON(): Creating new request")
	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(jsonStr))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	if c.token != "" {
		req.Header.Set("X-Cookie", "token="+c.token)
	}

	if c.accessKey != "" && c.secretKey != "" {
		header := fmt.Sprintf("accessKey=%s; secretKey=%s;", c.accessKey, c.secretKey)
		req.Header.Set("X-ApiKeys", header)
	}

	c.debugln("putWithJSON(): Executing request")
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	c.debugln("putWithJSON(): Reading body of response")
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}

	return resp.StatusCode, body, nil
}
