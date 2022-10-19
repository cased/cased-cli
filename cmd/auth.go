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
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/containerd/console"
	"github.com/matthewhartstonge/pkce"
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
	// auth requires exactly one positional argument, a cased-shell instance hostname
	Args: cobra.ExactArgs(1),
	Run:  login,
}

func login(cmd *cobra.Command, args []string) {
	var token string
	var authCode string

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

	// Generate a secure code verifier!
	codeVerifier, err := pkce.GenerateCodeVerifier(96)
	if err != nil {
		log.Fatalln("Unable to generate code verifier:", err)
	}

	codeChallenge, err := pkce.GenerateCodeChallenge(pkce.S256, codeVerifier)
	if err != nil {
		log.Fatalln("Unable to generate code challenge:", err)
	}

	loginURL := fmt.Sprintf("https://%s/%s", casedShell, loginAPI)

	req, err := http.NewRequest("GET", loginURL, nil)

	loginArgs := url.Values{}
	loginArgs.Add("cc", codeChallenge)
	req.URL.RawQuery = loginArgs.Encode()

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln("[*] ERROR: fetching auth URL from cased-shell:", err)
	}
	defer resp.Body.Close()

	var data map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		log.Fatalln("[*] ERROR: Invalid response from cased-shell server:", err)
	}

	authURL, ok := data["auth_url"]
	if !ok {
		log.Fatalln("[*] ERROR: Invalid response, 'auth_url' is missing")
	}

	pollURL, ok := data["poll_url"]
	if !ok {
		log.Fatalln("[*] ERROR: Invalid response, 'poll_url' is missing.")
	}

	tokenURL, ok := data["token_url"]
	if !ok {
		log.Fatalln("[*] ERROR: Invalid response, 'token_url' is missing.")
	}

	openbrowser(authURL.(string))

	log.Print("Waiting for authentication ")

	// Poll the API for authorization_code.
	const MaxIterations = 30
	for i := 0; i < MaxIterations; i++ {
		resp, err := http.Get(pollURL.(string))
		if err != nil {
			log.Fatal("[*] ERROR: Unable to get authorization code:", err)
		}

		if resp.StatusCode == http.StatusOK {
			var data map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&data)
			if err != nil {
				log.Fatal("[*] ERROR: Invalid response from cased-shell server:", err)
			}

			ac, ok := data["authorization_code"]
			if !ok {
				log.Fatal("[*] ERROR: Invalid response, 'authorization_code' is missing")
			}

			authCode = ac.(string)

			break
		}

		fmt.Print(".")
		time.Sleep(time.Second)
	}

	if authCode == "" {
		log.Fatalln("[*] Authentication timed out, exiting...")
	}

	req, err = http.NewRequest("GET", tokenURL.(string), nil)

	tokenArgs := url.Values{}
	tokenArgs.Add("authorization_code", authCode)
	tokenArgs.Add("cc", codeVerifier)
	req.URL.RawQuery = tokenArgs.Encode()

	respToken, err := client.Do(req)
	if err != nil {
		log.Fatalln("[*] ERROR: fetching token from cased-shell:", err)
	}
	defer respToken.Body.Close()

	var tokenData map[string]interface{}
	err = json.NewDecoder(respToken.Body).Decode(&tokenData)
	if err != nil {
		log.Fatalln("[*] ERROR: Fetching token, invalid response from cased-shell server:", err)
	}

	tk, ok := tokenData["token"]
	if !ok {
		log.Fatalln("[*] ERROR: Invalid response, 'token' is missing")
	}

	token = tk.(string)

	fmt.Println()
	log.Println("Authentication successful")

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

	log.Println("Connecting to cased-server...")

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
	term := os.Getenv("TERM")
	if term == "" {
		term = "xterm"
	}

	current := console.Current()
	defer current.Reset()

	w := 40
	h := 80

	if ws, err := current.Size(); err == nil {
		w = int(ws.Width)
		h = int(ws.Height)
	}

	if err := session.RequestPty(term, h, w, modes); err != nil {
		log.Fatal("Request for pseudo terminal failed: ", err)
	}

	if err := current.SetRaw(); err != nil {
		log.Fatal("Unable to set terminal mode to raw:", err)
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

	go func() {
		scanner := bufio.NewReader(stdout)
		data := make([]byte, 1024)
		for {
			n, err := scanner.Read(data)
			if err != nil {
				msg := ""
				if err != io.EOF {
					msg = ": " + err.Error()
				}
				log.Println("SSH Session ended", msg)
				current.Reset()
				os.Exit(0)
			}
			os.Stdout.Write(data[:n])
		}
	}()

	go func() {
		scanner := bufio.NewScanner(stderr)

		for scanner.Scan() {
			fmt.Println(scanner.Text())
		}
	}()

	session.Shell()

	scanner := bufio.NewReader(os.Stdin)
	b := make([]byte, 1)

	for {
		c, err := scanner.ReadByte()
		if err == io.EOF {
			return
		}
		b[0] = c
		if c == '/' {
			snippet := ShowSnippets()
			if snippet != "" {
				stdin.Write([]byte(snippet))
			}
		} else {
			stdin.Write(b)
		}
	}
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
