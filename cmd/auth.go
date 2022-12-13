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
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/containerd/console"
	"github.com/matthewhartstonge/pkce"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

var browserCmd *exec.Cmd

const (
	loginAPI            = "v2/api/auth"
	snippetsTriggerTime = 500 * time.Millisecond
)

type stdinReader struct {
	detached  atomic.Bool
	stdinChan chan []byte
	reader    *bufio.Reader
	lastInput []byte
}

// TestPrompt and TestAuth represent data loaded from integration test script.
type TestPrompt struct {
	Name     string // prompt name
	Matches  string
	Commands []struct {
		Cmd      string // command to execute
		Expected string // expected output
	}
}
type TestAuth struct {
	Prompts []TestPrompt
}

// TestAuthData stores integration test script data for testing the auth command.
var TestAuthData TestAuth

func (r *stdinReader) detach() {
	r.detached.Store(true)
	select {
	case <-r.stdinChan:
		r.reader.UnreadByte()
	default:
		return
	}
}

func (r *stdinReader) attach() {
	// Send last input read from bubbletea back to our app
	r.detached.Store(false)
	r.stdinChan <- r.lastInput
	r.lastInput = nil
}

func (r *stdinReader) isDetached() bool {
	return r.detached.Load()
}

var sharedStdinReader stdinReader = stdinReader{
	reader:    bufio.NewReader(os.Stdin),
	stdinChan: make(chan []byte),
}

func (r *stdinReader) readLoop() {
	var buffer [32]byte
	for {
		n, err := r.reader.Read(buffer[:])
		if err != nil {
			close(r.stdinChan)
			return
		}
		// Keep last input read from bubbletea app
		// When we close the bubbletea app (snippets), send the last
		// input back to our app so we don't lose it.
		if r.detached.Load() {
			r.lastInput = make([]byte, n)
			copy(r.lastInput, buffer[:n])
		}
		// debug(fmt.Sprintf("read: got %d bytes. is_detached=%v", n, r.detached.Load()))
		r.stdinChan <- buffer[:n]
	}
}

func (r *stdinReader) Read(p []byte) (n int, err error) {
	b, ok := <-r.stdinChan

	if !ok {
		return 0, errors.New("stdin channel is closed")
	}

	copy(p, b)

	return len(b), nil
}

const debugFileName = "ssh.log"

var (
	debugFile    *os.File
	debugWritter *bufio.Writer
	debug        func(string)
)

func debugImpl(msg string) {
	debugWritter.WriteString(msg + "\n")
	debugWritter.Flush()
}

func debugNull(msg string) {}

func init() {
	debug = debugNull

	if len(os.Getenv("DEBUG")) > 0 {
		var err error
		debugFile, err = os.OpenFile(debugFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0744)
		if err == nil {
			debugWritter = bufio.NewWriter(debugFile)
			debug = debugImpl
		}
	}

	rootCmd.AddCommand(authCmd)
}

// promptsCmd represents the prompts command
var authCmd = &cobra.Command{
	Use:     "auth instance.domain",
	Short:   "Authenticate cased-cli with the IDP",
	Long:    `Authenticate cased-cli with the IDP `,
	Example: "cased-cli auth instance.domain",
	// auth requires exactly one positional argument, a cased-shell instance hostname
	Args: cobra.ExactArgs(1),
	Run:  login,
}

var casedServer string
var casedHTTPServer string

func init() {
	// If CASED_SERVER is not set then cased-cli will get it during token exchange.
	casedServer = os.Getenv("CASED_SERVER")
	casedHTTPServer = os.Getenv("CASED_SERVER_API")
}

func login(cmd *cobra.Command, args []string) {
	casedShell := args[0]
	if casedShell == "" {
		fmt.Fprintf(os.Stderr, "[*] ERROR: cased-shell hostname must be a non-empty string.\n")
		os.Exit(1)
	}

	if casedServer != "" {
		log.Printf("CASED_SERVER: %s\n", casedServer)
	}

	if casedHTTPServer == "" {
		casedHTTPServer = fmt.Sprintf("https://%s/cased-server", casedShell)
	} else {
		log.Printf("CASED_SERVER_API: %v\n", casedHTTPServer)
	}

	// Generate a secure code verifier!
	codeVerifier, err := pkce.GenerateCodeVerifier(96)
	if err != nil {
		log.Fatalf("[*] ERROR: Unable to generate code verifier: %v\n", err)
	}

	codeChallenge, err := pkce.GenerateCodeChallenge(pkce.S256, codeVerifier)
	if err != nil {
		log.Fatalf("[*] ERROR: Unable to generate code challenge: %v\n", err)
	}

	loginURL := fmt.Sprintf("https://%s/%s", casedShell, loginAPI)

	req, err := http.NewRequest("GET", loginURL, nil)

	// If cased-cli is running in test mode, skip authentication.
	if testMode {
		req.Header.Add("X-SKIP-AUTH", "true")
	}

	loginArgs := url.Values{}
	loginArgs.Add("cc", codeChallenge)
	req.URL.RawQuery = loginArgs.Encode()

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[*] ERROR: fetching auth URL: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	var data map[string]interface{}
	var respCopy []byte
	if os.Getenv("DEBUG") == "trace" {
		// keep a copy of response for dumping it on errors.
		respCopy, err = ioutil.ReadAll(resp.Body)
		if err == nil {
			err = json.Unmarshal(respCopy, &data)
		}
	} else {
		err = json.NewDecoder(resp.Body).Decode(&data)
	}
	if err != nil {
		log.Printf("[*] ERROR: Unable to authenticate: domain=%s\n", casedShell)
		log.Printf("HTTP response status: %d/%s\n", resp.StatusCode, resp.Status)
		if resp.StatusCode == http.StatusOK {
			log.Println("Unexpected response format")
			if os.Getenv("DEBUG") == "trace" {
				dumpFile, err := os.CreateTemp(".", "resp_*.tmp")
				if err == nil {
					defer dumpFile.Close()
					dumpFile.Write(respCopy)
				}
				log.Printf("Trace mode enabled, HTTP response can be checked on file %q\n", dumpFile.Name())
			}
		}
		os.Exit(1)
	}

	token, err := getToken(data, codeVerifier)
	if err != nil {
		log.Fatal("[*] ERROR: ", err)
	}

	log.Println("Authentication successful")
	log.Println("Fetching remote data...")

	if err = fetchSnippets(casedHTTPServer, token); err != nil {
		log.Fatalln("[*] ERROR: Unable to fetch remote data: ", err)
	}

	connect(casedServer, token)
}

// getToken parses the response from cased-shell then attempts to launch a web browser
// which directs the user to the login page (auth_url).
// When running integration tests, the token is directly sent by cased-shell in the initial response.
func getToken(data map[string]interface{}, codeVerifier string) (string, error) {
	// In test mode the first cased-shell response must contain a valid token.
	// The response is in the format: {"token": "value", "status": "ok|error", "cased_server": "address:port"}
	if testMode {
		if err := checkFields(data, "status", "token"); err != nil {
			return "", fmt.Errorf(`%s (integration test)`, err)
		}

		if data["status"].(string) != "ok" {
			return "", errors.New("Internal server error (integration test)")
		}

		if data["token"].(string) == "" {
			return "", errors.New(`Invalid response: "token" is empty (integration test)`)
		}

		if casedServer == "" {
			// CASED_SERVER env was not provided, it must be retrieved from cased-shell
			// along with the token.
			srv, ok := data["cased_server"]
			if !ok {
				return "", errors.New(`Invalid response: "cased_server" is missing`)
			}
			casedServer = srv.(string)
		}

		return data["token"].(string), nil
	}

	if err := checkFields(data, "auth_url", "poll_url", "token_url"); err != nil {
		return "", err
	}

	authURL := data["auth_url"].(string)
	pollURL := data["poll_url"].(string)
	tokenURL := data["token_url"].(string)

	if !openbrowser(authURL) {
		fmt.Println("Please access the URL below in order to proceed with the authentication:")
		fmt.Println(authURL)
	}

	fmt.Print("Waiting for authentication...")

	token, err := pollToken(pollURL, tokenURL, codeVerifier)
	if err != nil {
		return "", err
	}

	return token, nil
}

// pollToken polls the poll_url sent by cased-shell in order to get an
// authorization code (available after user authentication in the web browser).
// Then, it attempts to get a token from token_url using the generated codeVerifier/
// authentication_code provided.
// More about the authorization flow on: https://www.oauth.com/oauth2-servers/device-flow/
func pollToken(pollURL, tokenURL, codeVerifier string) (string, error) {
	var authCode string

	// Start polling after some delay (web browser opening, user filling in credentials, etc...)
	time.Sleep(5 * time.Second)

	// try to get token every 3 secs
	const TryInterval = 3 * time.Second
	const MaxTries = 30

	// Poll the API for authorization_code.
	for i := 0; i < MaxTries; i++ {
		resp, err := http.Get(pollURL)
		if err != nil {
			return "", fmt.Errorf("Unable to get authorization code (poll URL): %v", err)
		}

		if resp.StatusCode == http.StatusOK {
			var data map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&data)
			if err != nil {
				return "", fmt.Errorf("Invalid response (poll URL): %v", err)
			}

			ac, ok := data["authorization_code"]
			if !ok {
				return "", errors.New(`Invalid response: "authorization_code" is missing`)
			}

			authCode = ac.(string)

			break
		}

		fmt.Print(".")
		time.Sleep(TryInterval)
	}

	if authCode == "" {
		return "", errors.New("Authentication timed out, exiting...")
	}

	req, err := http.NewRequest("GET", tokenURL, nil)

	tokenArgs := url.Values{}
	tokenArgs.Add("authorization_code", authCode)
	tokenArgs.Add("cc", codeVerifier)
	req.URL.RawQuery = tokenArgs.Encode()

	client := http.Client{}
	respToken, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("Failed to fetch token_url (%d/%s): %v", respToken.StatusCode, respToken.Status, err)
	}
	defer respToken.Body.Close()

	var data map[string]interface{}
	err = json.NewDecoder(respToken.Body).Decode(&data)
	if err != nil {
		return "", fmt.Errorf("Unable to parse response (token_url): %v", err)
	}

	tk, ok := data["token"]
	if !ok {
		return "", errors.New(`Invalid response (token_url): "token" is missing`)
	}

	if casedServer == "" {
		// CASED_SERVER env was not provided, it must be retrieved from cased-shell
		// along with the token.
		srv, ok := data["cased_server"]
		if !ok {
			return "", errors.New(`Invalid response (token_url): "cased_server" is missing`)
		}
		casedServer = srv.(string)
	}

	return tk.(string), nil
}

func connect(host, token string) {
	var connectedToPrompt atomic.Bool
	var testTimer *time.Timer
	var testTimerExpired atomic.Bool

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

	if testMode {
		testTimer = time.NewTimer(2 * time.Second)
	}

	go func() {
		handshake := []byte{0xde, 0xad, 0xbe, 0xef}
		disconnectedHandshake := []byte{0xef, 0xbe, 0xad, 0xde}
		scanner := bufio.NewReader(stdout)
		data := make([]byte, 1024)
		hsPtr := 0 // handshake pointer to the current expected byte

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

			if testMode && !testTimerExpired.Load() {
				testTimer.Reset(2 * time.Second)
			}

			var hsBuffer []byte
			if !connectedToPrompt.Load() {
				hsBuffer = handshake
			} else {
				hsBuffer = disconnectedHandshake
			}

			// debug(fmt.Sprintf("ssh (raw): len=%d, %v", n, string(data[:n])))
			// look for handshake (connected to or disconnected from target prompt)
			for i, b := range data[:n] {
				if b == hsBuffer[hsPtr] {
					hsPtr++
					if hsPtr == len(hsBuffer) {
						// Handshake found.
						// Send received data to the terminal but filter the handshake itself.
						if (i + 1) == hsPtr {
							// handshake found right in the start of the packet, i.e. data[:hsPtr] == handshake
							os.Stdout.Write(data[hsPtr:])
						} else {
							// handshake found after the start of the packet
							os.Stdout.Write(data[:(i-hsPtr)+1]) // write first bytes before the handshake
							os.Stdout.Write(data[i+1:])         // write remaining bytes
						}
						hsPtr = 0
						connectedToPrompt.Store(!connectedToPrompt.Load())
						continue
					}
				} else if hsPtr > 0 {
					// Reset handshake pointer, mismatched data
					hsPtr = 0
				}
			}
			// filtered := bytes.Replace(data[:n], []byte("\x1b[?2004l"), []byte{}, -1)
			// filtered = bytes.Replace(filtered, []byte("\x1b[?2004h"), []byte{}, -1)
			// filtered = bytes.Replace(filtered, []byte("]0;"), []byte{}, -1)
			// debug(fmt.Sprintf("STDOUT (b): [%v]", filtered))
			// debug(fmt.Sprintf("STDOUT (s): [%v]", string(filtered)))
			os.Stdout.Write(data[:n])
		}
	}()

	// remote stderr reader
	go func() {
		scanner := bufio.NewScanner(stderr)

		for scanner.Scan() {
			fmt.Fprint(os.Stderr, scanner.Text())
		}
	}()

	session.Shell()

	var timer *time.Timer
	timerIsOn := false

	go sharedStdinReader.readLoop()

	for {
		if timerIsOn {
			select {
			case <-timer.C:
				sharedStdinReader.detach() // give control of stdin to bubbletea
				timerIsOn = false
				snippet := ShowSnippetsWithReader(&sharedStdinReader)
				sharedStdinReader.attach()
				if snippet != "" {
					stdin.Write([]byte(snippet))
				}
			case data, ok := <-sharedStdinReader.stdinChan:
				if !ok {
					return
				}
				timer.Stop()
				timerIsOn = false
				stdin.Write([]byte("/"))
				stdin.Write(data)
			}
		} else if testMode {
			select {
			case <-testTimer.C:
				testTimerExpired.Store(true)
				integrationTest(stdin)
				return
			}
		} else {
			select {
			case data, ok := <-sharedStdinReader.stdinChan:
				if !ok {
					return
				}
				if data[0] == '/' &&
					len(data) == 1 &&
					len(remoteSnippetsData) > 0 &&
					connectedToPrompt.Load() {
					timerIsOn = true
					timer = time.NewTimer(snippetsTriggerTime)
				} else {
					stdin.Write(data)
				}
			}
		}
	}
}

func openbrowser(url string) bool {
	switch runtime.GOOS {
	case "linux":
		browserCmd = exec.Command("xdg-open", url)
	case "windows":
		browserCmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		browserCmd = exec.Command("open", url)
	default:
		log.Println("Unknow OS platform")
		return false
	}

	if err := browserCmd.Start(); err != nil {
		log.Println("Unable to launch web browser: ", err)
		return false
	}

	return true
}

func checkFields(data map[string]interface{}, fields ...string) error {
	for _, field := range fields {
		if _, ok := data[field]; !ok {
			return fmt.Errorf(`Invalid response: %q is missing`, field)
		}
	}

	return nil
}

// sendTestCommands connect to the prompts specified in the integration test script,
// then send the commands and check for expected results.
func integrationTest(session io.WriteCloser) {
	sendBytes := func(data []byte) {
		n, err := session.Write(data)
		if n != len(data) || err != nil {
			log.Fatal("SSH write failed: ", err)
		}
	}
	for _, prompt := range TestAuthData.Prompts {
		sendBytes([]byte("/")) // Triggers list search (for Prompt)
		time.Sleep(2 * time.Second)
		sendBytes([]byte(prompt.Name)) // Look for a prompt matching this name.
		time.Sleep(2 * time.Second)
		sendBytes([]byte("\n")) // select Prompt
		time.Sleep(2 * time.Second)
		sendBytes([]byte("\r\n")) // send selection over SSH
		time.Sleep(5 * time.Second)

		for _, command := range prompt.Commands { // Send commands to the prompt.
			sendBytes([]byte(command.Cmd))
			sendBytes([]byte("\r\n"))
			time.Sleep(time.Second)
		}
		session.Write([]byte("exit\n"))
		time.Sleep(time.Second)
		log.Println("Integration test results: success")
	}
}
