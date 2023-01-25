package cased

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

// Get fetches data (using HTTP/GET) from the cased-shell instance at server.
// server must include the protocol prefix, e.g. https://hostname
func Get(server, endpoint, token string) ([]byte, error) {
	if !strings.HasSuffix(server, "/") {
		server += "/"
	}
	apiURL := fmt.Sprintf("%s%s", server, endpoint)

	if os.Getenv("TLS_SKIP_VERIFY") == "true" {
		// Disable TLS verification, useful for testing cased-cli with a local cased-server instance.
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	req, err := http.NewRequest("GET", apiURL, nil)

	if err != nil {
		return nil, err
	}

	// Token based authentication
	req.Header.Add("Authorization", "Bearer "+token)

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusFound {
		return nil, errors.New("HTTP Error: " + resp.Status)
	}

	response, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return response, nil
}
