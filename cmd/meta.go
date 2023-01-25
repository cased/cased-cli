package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/cased/cased-cli/cased"
)

// getMetaData fetches metadata information from a cased-shell instance.
// Information includes cased-server's hostname/IP and any other relevant data
// required by cased-cli to work properly.
func getMetaData(server, token string) (map[string]string, error) {
	const endpoint = "/api/meta"

	metaData, err := cased.Get(server, endpoint, token)
	if err != nil {
		return nil, err
	}

	// metadata validation
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
