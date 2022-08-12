/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"strconv"

	"github.com/cased/cased-cli/cased"
	sshclient "github.com/helloyi/go-sshclient"
	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

// type Prompt struct {
// 	Hostname    string `json:"hostname"`
// 	Port        string `json:"port"`
// 	Username    string `json:"username"`
// 	IpAddress   string `json:"ip_address"`
// 	Name        string `json:"name"`
// 	Description string `json:"description"`
//   "jump_command": null,
//   "shell_command": null,
//   "pre_download_command": null,
//   "kind": null,
//   "provider": null,
//   "labels": {
//     "network": "localhost",
//     "app": "heroku"
//   },
//   "annotations": {},
//   "principals": [],
//   "featured": true,
//   "prompt_for_key": false,
//   "prompt_for_username": false,
//   "proxy_jump_selector": {},
//   "close_terminal_on_exit": true
// }

type Prompt struct {
	Name        string
	Description string
}

// promptsCmd represents the prompts command
var promptsCmd = &cobra.Command{
	Use:   "prompts",
	Short: "List available prompts",
	Long:  `List available prompts`,
	Run: func(cmd *cobra.Command, args []string) {

		response, _, err := cased.GET("/api/prompts", nil)
		if err != nil {
			os.Stderr.WriteString(err.Error() + "\n")
			os.Exit(1)
		}

		err = ioutil.WriteFile("prompts.txt", []byte(response), 0)

		var data map[string]interface{}
		json.Unmarshal([]byte(response), &data)

		prompts_map := make(map[int]map[string]interface{})

		available_prompts := make([]Prompt, 0)

		// Populate prompts map, where key is the index of selected prompt in\
		// the UI list, and value is a dictionary with prompt data fields:
		//    description, hostname, etc...
		// Also create a slice of Prompt objects to populate UI (available_prompts)
		for i, v := range data["data"].([]interface{}) {
			// data["data"] is an array of json objects (Prompt data)
			// The way go decodes dictionaries is to map[string]interface{}
			prom := v.(map[string]interface{})
			var description string = "None"

			if prom["description"] != nil {
				description = prom["description"].(string)
			}

			// Map selection index in UI to the prompt dict.
			prompts_map[i] = prom

			// Populate prompt's list.
			available_prompts = append(available_prompts, Prompt{
				Name:        prom["name"].(string),
				Description: description,
			})
		}

		// A template to display prompts.
		templates := &promptui.SelectTemplates{
			Label:    "{{ . }}?",
			Active:   "\U0001F336 {{ .Name | cyan }}",
			Inactive: "  {{ .Name | cyan }}",
			Selected: "\U0001F336 {{ .Name | red | cyan }}",
			Details: `
	--------- Prompt ----------
	{{ "Name:" | faint }}	{{ .Name }}
	{{ "Description:" | faint }}	{{ .Description }}`,
		}

		prompt := promptui.Select{
			Label:     "Select prompt:",
			Items:     available_prompts,
			Size:      len(available_prompts),
			Templates: templates,
		}

		idx, result, err := prompt.Run()

		if err != nil {
			fmt.Printf("Prompt failed %v\n", err)
			return
		}

		// Build POST params
		target_prompt := prompts_map[idx]
		params := url.Values{}
		for key := range target_prompt {
			switch target_prompt[key].(type) {
			case string:
				params.Add(key, target_prompt[key].(string))
			case int:
				params.Add(key, strconv.Itoa(target_prompt[key].(int)))
			case bool:
				v := target_prompt[key].(bool)
				if v {
					params.Add(key, "True")
				} else {
					params.Add(key, "False")
				}
			case map[string]interface{}:
				jstr, err := json.Marshal(target_prompt[key])
				if err == nil {
					params.Add(key, string(jstr))
				}
			case []interface{}:
				params.Add(key, fmt.Sprintf("%s", target_prompt[key]))
			case nil:
				params.Add(key, "")
			default:
				fmt.Fprintf(os.Stderr, "[*] ERROR: Unknown key type: key=(%s), type=%T\n", key, target_prompt[key])
				fmt.Fprintf(os.Stderr, "When creating prompt")
			}
		}

		response, _, err = cased.POST("/", params)
		if err == nil {
			ioutil.WriteFile("post.txt", []byte(response), 0660)
		} else {
			fmt.Fprintf(os.Stderr, "[*] Failed to connect to prompt.")
			os.Exit(1)
		}

		var resp_map map[string]interface{}
		json.Unmarshal([]byte(response), &resp_map)
		// for k := range resp_map {
		// 	fmt.Printf("key: %s, value=%v, type=%T\n", k, resp_map[k], resp_map[k])
		// }

		id := resp_map["id"].(string)

		cased.Websocket(id)

		os.Exit(0)

		fmt.Printf("Connecting to %s\n...", result)

		client, err := sshclient.DialWithKey("54.201.48.136:22", "ec2-user", "/Users/trishula/.ssh/test-key.pem")
		if err != nil {
			fmt.Printf("Prompt failed %v\n", err)
			return
		}

		config := &sshclient.TerminalConfig{
			Term:   "xterm-256color",
			Height: 40,
			Weight: 80,
			Modes: ssh.TerminalModes{
				ssh.TTY_OP_ISPEED: 14400,
				ssh.TTY_OP_OSPEED: 14400,
				ssh.ECHO:          1,
			},
		}

		fd := int(os.Stdin.Fd())
		state, err := terminal.MakeRaw(fd)
		if err != nil {
			fmt.Printf("Prompt failed %v\n", err)
			return
		}

		if err := client.Terminal(config).Start(); err != nil {
			fmt.Printf("error starting terminal")
			return
		}

		defer terminal.Restore(fd, state)
		defer client.Close()
	},
}

func init() {
	rootCmd.AddCommand(promptsCmd)
}
