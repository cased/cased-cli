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
	var connectedToPrompt atomic.Bool

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

			var hsBuffer []byte
			if !connectedToPrompt.Load() {
				hsBuffer = handshake
			} else {
				hsBuffer = disconnectedHandshake
			}

			// debug(fmt.Sprintf("ssh (raw): len=%d, %v", n, data[:n]))
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
		} else {
			select {
			case data, ok := <-sharedStdinReader.stdinChan:
				if !ok {
					return
				}
				if data[0] == '/' && len(data) == 1 && connectedToPrompt.Load() {
					timerIsOn = true
					timer = time.NewTimer(snippetsTriggerTime)
				} else {
					stdin.Write(data)
				}
			}
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
