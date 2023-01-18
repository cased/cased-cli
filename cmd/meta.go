package cmd

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

func getMetaData(server, token string) (map[string]string, error) {
	const endpoint = "/api/meta"
	apiURL := fmt.Sprintf("%s%s", server, endpoint)

	var err error
	var req *http.Request

	if os.Getenv("TLS_SKIP_VERIFY") == "true" {
		// Disable TLS verification
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	req, err = http.NewRequest("GET", apiURL, nil)

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

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	metaData := body

	// Snippets validation
	if len(metaData) > 0 {
		var data map[string]string

		if err := json.Unmarshal(metaData, &data); err != nil {
			return nil, fmt.Errorf("invalid meta response: %v", metaData)
		} else if _, ok := data["cased_server"]; !ok {
			return nil, fmt.Errorf("invalid meta data: \"cased_server\" field is missing")
		}
		return data, nil
	} else {
		return nil, fmt.Errorf("empty response")
	}
}
