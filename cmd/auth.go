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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cased/cased-cli/cased"
	"github.com/cased/cased-cli/integration"
	"github.com/containerd/console"
	"github.com/google/uuid"
	"github.com/matthewhartstonge/pkce"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

// cased-cli constant settings
const (
	snippetsTriggerTime = 500 * time.Millisecond
	clientID            = "cased-cli" // OAUTH/dex "client_id"
)

var (
	stateUUID uuid.UUID
)

func init() {
	stateUUID = uuid.New()

	rootCmd.AddCommand(authCmd)
}

// stdinReader wraps reads from stdin.
// It implements the io.Reader interface: https://pkg.go.dev/io#Reader,
// which allows us to provide it as the input reader for bubbletea:
// e.g tea.NewProgram(m, tea.WithInput(stdinReader{})
//
// At any given time, cased-cli can be running in one of two modes:
//
//	1: bubble tea mode: In this mode, we say we are "detached" from stdin,
//	   all input is read and processed first by the bubbletea library.
//
//	2: normal mode: In this mode, cased-cli consumes stdin input normally.
//
// The reason we want to control the input is that when switching from
// bubbletea mode to normal mode, bubbletea may have "swallowed" the input,
// giving the impression that the keystroke was ignored by the app.
// If that happens, we send this "swallowed" data (lastInput) to
// cased-cli again so we don't lose it.
type stdinReader struct {
	detached  atomic.Bool   // if detached, stdin input is being consumed by bubbletea.
	stdinChan chan []byte   // Send all data read from stdin to this channel.
	reader    *bufio.Reader // Read from stdin using a buffered reader, which allows to "unread" input.
	// keep last input read, when we switch from bubbletea to normal mode
	// if there was any pending data read, we forward it to stdinChan channel.
	// This allows cased-cli to not miss that input.
	lastInput []byte
}

// detach switches input mode from normal to bubbletea.
func (r *stdinReader) detach() {
	r.detached.Store(true)
	select {
	// stdin input not consumed by cased-cli, forward it to bubbletea.
	case <-r.stdinChan:
		r.reader.UnreadByte()
	default:
		return
	}
}

// attach switches input mode from bubbletea to normal
func (r *stdinReader) attach() {
	// Send last input read from bubbletea back to our app
	r.detached.Store(false)
	r.stdinChan <- r.lastInput
	r.lastInput = nil
}

func (r *stdinReader) isDetached() bool {
	return r.detached.Load()
}

// A shared stdin reader between cased-cli and bubbletea
// Both get input data from stdinChan channel.
var sharedStdinReader stdinReader = stdinReader{
	reader:    bufio.NewReader(os.Stdin),
	stdinChan: make(chan []byte),
}

// readLoop forward data read from stdin to the stdinReader channel.
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
			// cap on nil slice == 0
			if cap(r.lastInput) < n {
				r.lastInput = make([]byte, n)
			}
			copy(r.lastInput, buffer[:n])
		}
		fileLogger.Debug().
			Int("bytes", n).
			Bool("is_detached", r.detached.Load()).
			Msg("read")
		r.stdinChan <- buffer[:n]
	}
}

func (r *stdinReader) Read(p []byte) (n int, err error) {
	b, ok := <-r.stdinChan

	if !ok {
		return 0, errors.New("stdin channel is closed")
	}

	return copy(p, b), nil
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
		log.Info().Msgf("CASED_SERVER: %s", casedServer)
	}

	if casedHTTPServer == "" {
		casedHTTPServer = fmt.Sprintf("https://%s/cased-server", casedShell)
	} else {
		log.Info().Msgf("CASED_SERVER_API: %v", casedHTTPServer)
	}
	var issuer string
	var metaDataURL string

	if strings.HasPrefix(casedShell, "https://") {
		issuer = fmt.Sprintf("%s/idp", casedShell)
		metaDataURL = fmt.Sprintf("%s", casedShell)
	} else {
		issuer = fmt.Sprintf("https://%s/idp", casedShell)
		metaDataURL = fmt.Sprintf("https://%s", casedShell)
	}

	token, err := AuthorizeUser("cased-cli", issuer, "http://127.0.0.1:9993/callback")
	if err != nil {
		log.Fatal().Msg(err.Error())
	}

	log.Info().Msg("Authentication successful")
	log.Info().Msg("Fetching remote data...")

	metaData, err := cased.GetMetaData(metaDataURL, token)
	if err != nil {
		log.Fatal().Msgf("[*] ERROR: Unable to fetch metadata: %v", err)
	}

	if err := fetchSnippets(casedHTTPServer, token); err != nil {
		log.Fatal().Msgf("[*] ERROR: Unable to fetch snippets: %v", err)
	}

	if casedServer != "" {
		connect(casedServer, token)
	} else {
		connect(metaData["cased_server"], token)
	}
}

// AuthorizeUser implements the PKCE OAuth2 flow.
// If authentication succeeds, the token is return to the caller as string.
func AuthorizeUser(clientID string, issuer string, redirectURL string) (string, error) {
	var token string

	// Generate a secure code verifier!
	codeVerifier, err := pkce.GenerateCodeVerifier(96)
	if err != nil {
		return "", fmt.Errorf("[*] ERROR: Unable to generate code verifier: %v\n", err)
	}

	codeChallenge, err := pkce.GenerateCodeChallenge(pkce.S256, codeVerifier)
	if err != nil {
		return "", fmt.Errorf("[*] ERROR: Unable to generate code challenge: %v\n", err)
	}

	// setup a request to the auth endpoint
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/auth", issuer), nil)
	if err != nil {
		return "", err
	}

	loginArgs := url.Values{}
	loginArgs.Add("audience", issuer)
	loginArgs.Add("scope", "openid offline_access profile email")
	loginArgs.Add("response_type", "code")
	loginArgs.Add("state", stateUUID.String())
	loginArgs.Add("client_id", clientID)
	loginArgs.Add("redirect_uri", redirectURL)
	loginArgs.Add("code_challenge", codeChallenge)
	loginArgs.Add("code_challenge_method", "S256")
	req.URL.RawQuery = loginArgs.Encode()

	// Create a http server to wait for the authentication callback
	server := &http.Server{}

	var tokenExchangeError error
	var wg sync.WaitGroup
	wg.Add(1)

	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		// stop the server after handling the first request
		defer wg.Done()

		// parse the response from the authorization server
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")
		if code == "" || state == "" || state != stateUUID.String() {
			tokenExchangeError = errors.New("Authentication failed, invalid code/state.")
			sendResponse(w, tokenExchangeError.Error())
			return
		}

		// exchange the code and the verifier for an access token
		token, err = exchangeCodeForToken(issuer, clientID, codeVerifier, code, redirectURL)
		if err != nil {
			tokenExchangeError = fmt.Errorf("Unable to exchange code for token: %v", err)
			sendResponse(w, tokenExchangeError.Error())
			return
		}

		// tell the caller we're good
		sendResponse(w, "Authentication successful. You can close this window.\n")
	})

	// extract the port number from the redirectURL
	u, err := url.Parse(redirectURL)
	if err != nil {
		return "", fmt.Errorf("[*] ERROR: Unable to parse redirect URL: %v\n", err)
	}
	port := u.Port()

	// listen on that port
	listener, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		return "", fmt.Errorf("[*] ERROR: Unable to listen on port %s: %v\n", port, err)
	}

	// start the server in a separate goroutine
	go server.Serve(listener)

	if !openbrowser(req.URL.String()) {
		fmt.Println("Please access the URL below in order to proceed with the authentication:")
		fmt.Println(req.URL.String())
	}

	// Wait for auth callback handler
	wg.Wait()

	// Exit if failed to exchange code for token.
	if tokenExchangeError != nil {
		log.Error().Err(tokenExchangeError).Msg("")
		select {
		case <-time.After(1 * time.Second):
			stop(server)
			os.Exit(1)
		}
	}

	// Stop the server in a background goroutine
	go func() {
		// Wait a little delay to ensure that client has receive an answer.
		select {
		case <-time.After(3 * time.Second):
			stop(server)
		}
	}()

	return token, nil
}

func sendResponse(w http.ResponseWriter, message string) {
	fmt.Fprint(w, message)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

func stop(server *http.Server) {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer func() { cancel() }()
	server.Shutdown(shutdownCtx)
}

// exchangeCodeForToken trades the authorization code for an access token
func exchangeCodeForToken(issuer string, clientID string, codeVerifier string, authorizationCode string, redirectURL string) (string, error) {
	// build the request body
	body := url.Values{}
	body.Add("grant_type", "authorization_code")
	body.Add("client_id", clientID)
	body.Add("code_verifier", codeVerifier)
	body.Add("code", authorizationCode)
	body.Add("redirect_uri", redirectURL)

	// send the request
	resp, err := http.PostForm(fmt.Sprintf("%s/token", issuer), body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// extract into a map
	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", err
	}

	return data["access_token"].(string), nil
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

	log.Info().Msg("Connecting to cased-server...")

	client, err := ssh.Dial("tcp", host, config)
	if err != nil {
		log.Fatal().Msgf("Failed to dial: %v", err)
	}
	defer client.Close()

	// Each ClientConn can support multiple interactive sessions,
	// represented by a Session.
	session, err := client.NewSession()
	if err != nil {
		log.Fatal().Msgf("Failed to create session: %v", err)
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

	if ws, werr := current.Size(); werr == nil {
		w = int(ws.Width)
		h = int(ws.Height)
	}

	if err = session.RequestPty(term, h, w, modes); err != nil {
		log.Fatal().Msgf("Request for pseudo terminal failed: %v", err)
	}

	if err = current.SetRaw(); err != nil {
		log.Fatal().Msgf("Unable to set terminal mode to raw: %v", err)
	}

	var stdin io.WriteCloser
	var stdout, stderr io.Reader

	stdin, err = session.StdinPipe()
	if err != nil {
		log.Fatal().Err(err).Msg("Creating stdin pipe")
	}

	stdout, err = session.StdoutPipe()
	if err != nil {
		log.Fatal().Err(err).Msg("Creating stdout pipe")
	}

	stderr, err = session.StderrPipe()
	if err != nil {
		log.Fatal().Err(err).Msg("Creating stderr pipe")
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
				msg := "SSH Session ended"
				if err != io.EOF {
					msg += ": " + err.Error()
				}
				log.Info().Msg(msg)
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

			fileLogger.Debug().
				Int("len", n).
				Str("raw data", string(data[:n])).
				Msg("ssh read")

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
				integration.RunTest(stdin)
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
					fetchedSnippets != nil &&
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
	var browserCmd *exec.Cmd

	switch runtime.GOOS {
	case "linux":
		browserCmd = exec.Command("xdg-open", url)
	case "windows":
		browserCmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		browserCmd = exec.Command("open", url)
	default:
		log.Error().Msg("Unknow OS platform")
		return false
	}

	if err := browserCmd.Start(); err != nil {
		log.Error().Err(err).Msg("Unable to launch web browser")
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
