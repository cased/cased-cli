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
	"fmt"
	"os"

	sshclient "github.com/helloyi/go-sshclient"
	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

// promptsCmd represents the prompts command
var promptsCmd = &cobra.Command{
	Use:   "prompts",
	Short: "List available prompts",
	Long:  `List available prompts`,
	Run: func(cmd *cobra.Command, args []string) {
		prompt := promptui.Select{
			Label: "Select prompt:",
			Items: []string{"bastion-one", "rails console", "bastion-two", "heroku-app"},
		}

		_, result, err := prompt.Run()

		if err != nil {
			fmt.Printf("Prompt failed %v\n", err)
			return
		}

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
