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
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

var browserCmd *exec.Cmd

const loginAPI = "v2/api/auth"

func init() {
	rootCmd.AddCommand(authCmd)
}

// promptsCmd represents the prompts command
var authCmd = &cobra.Command{
	Use:     "auth instance.domain",
	Short:   "Authenticate cased-cli with the IDP",
	Long:    `Authenticate cased-cli with the IDP `,
	Example: "cased auth instance.domain",
	Args:    cobra.ExactArgs(1),
	Run:     login,
}

func login(cmd *cobra.Command, args []string) {
	var token string
	casedServer := os.Getenv("CASED_SERVER")
	if casedServer == "" {
		fmt.Fprintf(os.Stderr, "[*] ERROR: CASED_SERVER env not found")
		os.Exit(1)
	}

	casedShell := args[0]
	if casedShell == "" {
		fmt.Fprintf(os.Stderr, "[*] ERROR: cased-shell hostname must be a non-empty string.")
		os.Exit(1)
	}

	loginURL := fmt.Sprintf("https://%s/%s", casedShell, loginAPI)
	resp, err := http.Get(loginURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[*] ERROR: fetching auth URL from cased-shell:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	var data map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[*] ERROR: Invalid response from cased-shell server:", err)
		os.Exit(1)
	}

	authURL, ok := data["auth_url"]
	if !ok {
		fmt.Fprintln(os.Stderr, "[*] ERROR: Invalid response, 'auth_url' is missing")
		os.Exit(1)
	}

	pollURL, ok := data["poll_url"]
	if !ok {
		fmt.Fprintln(os.Stderr, "[*] ERROR: Invalid response, 'poll_url' is missing.")
		os.Exit(1)
	}

	fmt.Println("Auth URL:", authURL)
	openbrowser(authURL.(string))

	fmt.Print("Waiting for authentication ")

	// Poll the API for token
	for {
		resp, err := http.Get(pollURL.(string))
		if err != nil {
			fmt.Fprintln(os.Stderr, "[*] ERROR: Unable to get access token:", err)
			os.Exit(1)
		}

		if resp.StatusCode == 200 {
			var data map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&data)
			if err != nil {
				fmt.Fprintln(os.Stderr, "[*] ERROR: Invalid response from cased-shell server:", err)
				os.Exit(1)
			}

			tk, ok := data["token"]
			if !ok {
				fmt.Fprintln(os.Stderr, "[*] ERROR: Invalid response, unable to parse token")
				os.Exit(1)
			}

			token = tk.(string)

			break
		}

		fmt.Print(".")
		time.Sleep(time.Second)
	}

	fmt.Println("\nToken:", token)
	connect(casedServer, token)
}

func connect(host, token string) {
	config := &ssh.ClientConfig{
		User: "cased",
		Auth: []ssh.AuthMethod{
			ssh.Password(token),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", host, config)
	if err != nil {
		log.Fatal("Failed to dial: ", err)
	}
	defer client.Close()

	// Each ClientConn can support multiple interactive sessions,
	// represented by a Session.
	session, err := client.NewSession()
	if err != nil {
		log.Fatal("Failed to create session: ", err)
	}
	defer session.Close()

	// Set up terminal modes
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	// Request pseudo terminal
	if err := session.RequestPty("xterm", 40, 80, modes); err != nil {
		log.Fatal("request for pseudo terminal failed: ", err)
	}

	var stdin io.WriteCloser
	var stdout, stderr io.Reader

	stdin, err = session.StdinPipe()
	if err != nil {
		log.Fatal(err.Error())
	}

	stdout, err = session.StdoutPipe()
	if err != nil {
		log.Fatal(err.Error())
	}

	stderr, err = session.StderrPipe()
	if err != nil {
		log.Fatal(err.Error())
	}

	wr := make(chan []byte, 10)

	go func() {
		for {
			select {
			case d := <-wr:
				_, err := stdin.Write(d)
				if err != nil {
					fmt.Println(err.Error())
				}
			}
		}
	}()

	go func() {
		scanner := bufio.NewScanner(stdout)
		for {
			if tkn := scanner.Scan(); tkn {
				rcv := scanner.Bytes()
				raw := make([]byte, len(rcv))
				copy(raw, rcv)
				fmt.Println(string(raw))
			} else {
				if scanner.Err() != nil {
					fmt.Println(scanner.Err())
				return
			}
		}
	}()

	go func() {
		scanner := bufio.NewScanner(stderr)

		for scanner.Scan() {
			fmt.Println(scanner.Text())
		}
	}()

	session.Shell()

	for {
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		text := scanner.Text()

		wr <- []byte(text + "\n")
	}

	fmt.Println("DONE!")
}

func openbrowser(url string) {
	switch runtime.GOOS {
	case "linux":
		browserCmd = exec.Command("xdg-open", url)
	case "windows":
		browserCmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		browserCmd = exec.Command("open", url)
	default:
		log.Fatal("unsupported platform")
	}

	if err := browserCmd.Start(); err != nil {
		log.Fatal(err)
	}
}
