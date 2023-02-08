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
	"github.com/cased/cased-cli/iowrapper"
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
	stateUUID       uuid.UUID
	casedServer     string
	casedHTTPServer string
)

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

func init() {
	stateUUID = uuid.New()

	// If CASED_SERVER is not set then cased-cli will get it during token exchange.
	casedServer = os.Getenv("CASED_SERVER")
	casedHTTPServer = os.Getenv("CASED_SERVER_API")

	rootCmd.AddCommand(authCmd)
}

func login(cmd *cobra.Command, args []string) {
	casedShell := args[0]
	if casedShell == "" {
		log.Fatal().Msg("cased-shell hostname must be a non-empty string")
	}

	if casedServer == "" {
		log.Info().Msg("CASED_SERVER: <autodetect from cased-shell metadata>")
	} else {
		log.Info().Msgf("CASED_SERVER: %s", casedServer)
	}

	if casedHTTPServer == "" {
		casedHTTPServer = fmt.Sprintf("https://%s/cased-server", casedShell)
	}

	log.Info().Msgf("CASED_SERVER_API: %v", casedHTTPServer)

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
		log.Fatal().Msgf("Unable to fetch metadata: %v", err)
	}

	if err := fetchSnippets(casedHTTPServer, token); err != nil {
		log.Warn().Msgf("Unable to fetch snippets: %v", err)
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
		return "", fmt.Errorf("Unable to generate code verifier: %v", err)
	}

	codeChallenge, err := pkce.GenerateCodeChallenge(pkce.S256, codeVerifier)
	if err != nil {
		return "", fmt.Errorf("Unable to generate code challenge: %v", err)
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
		return "", fmt.Errorf("Unable to parse redirect URL: %v", err)
	}
	port := u.Port()

	// listen on that port
	listener, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		return "", fmt.Errorf("Unable to listen on port %s: %v", port, err)
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
func exchangeCodeForToken(issuer, clientID, codeVerifier, authorizationCode, redirectURL string) (string, error) {
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

var (
	// Set when connected to a target prompt from which cased-server work as a bridge:
	// cased-cli <--> cased-server <--> cased-shell <--> target-prompt.
	// We have a simple handshake between cased-cli and cased-server to detect that
	// cased-cli has succesfully connected to a prompt.
	connectedToPrompt atomic.Bool
	testTimer         *time.Timer
	testTimerExpired  atomic.Bool
)

func connect(host, token string) {
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

	go sshReadStdout(stdout)
	go sshReadStderr(stderr)
	session.Shell()
	go sshSendInput(stdin)
}

// sshReadStdout reads remote stdout stream (output from commands executed remotely).
func sshReadStdout(stdout io.Reader) {
	scanner := bufio.NewReader(stdout)
	data := make([]byte, 1024)

	for {
		n, err := scanner.Read(data)
		if err != nil {
			msg := "SSH Session ended"
			if err != io.EOF {
				msg += ": " + err.Error()
			}
			log.Info().Msg(msg)
			return
		}

		// we got some data, update test timer if running integration tests (cased-cli test auth ...)
		// when this timer expires we're good to start sending test commands, as the remote
		// finished sending the initial ssh banner.
		if testMode && !testTimerExpired.Load() {
			testTimer.Reset(2 * time.Second)
		}

		fileLogger.Debug().
			Int("len", n).
			Str("raw data", string(data[:n])).
			Msg("ssh read")

		// look for handshake (connected to or disconnected from target prompt)
		if processHandshake(data[:n]) {
			continue
		}

		os.Stdout.Write(data[:n])
	}
}

func processHandshake(data []byte) bool {
	// cased-server sends this stream of bytes when user connects to a prompt.
	handshake := []byte{0xde, 0xad, 0xbe, 0xef}
	// cased-server sends this stream of bytes when user disconnects from a prompt.
	disconnectedHandshake := []byte{0xef, 0xbe, 0xad, 0xde}

	var hsBuffer []byte
	hsPtr := 0 // handshake pointer to the current expected byte

	if !connectedToPrompt.Load() {
		// not connected to a prompt yet, look for connected handshake bytes.
		hsBuffer = handshake
	} else {
		// cased-cli is connected to a prompt, look for a prompt-disconnected handshake.
		hsBuffer = disconnectedHandshake
	}

	// look for handshake (connected to or disconnected from target prompt)
	for i, b := range data {
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
				connectedToPrompt.Store(!connectedToPrompt.Load())
				return true
			}
		} else if hsPtr > 0 {
			// Reset handshake pointer, mismatched data
			hsPtr = 0
		}
	}

	return false
}

// sshReadStderr reads remote stderr stream.
func sshReadStderr(stderr io.Reader) {
	scanner := bufio.NewScanner(stderr)

	for scanner.Scan() {
		fmt.Fprint(os.Stderr, scanner.Text())
	}
}

// sshSendInput keeps processing user input and send it over to the remote ssh stdin stream.
func sshSendInput(stdin io.WriteCloser) {
	var snippetsTimer *time.Timer
	snippetsTimerIsOn := false

	sharedStdinReader := iowrapper.New(os.Stdin)
	// Read input from cased-cli (either cased-cli or bubbletea may be reading from stdin)
	go sharedStdinReader.ReadLoop()

	for {
		if snippetsTimerIsOn {
			select {
			case <-snippetsTimer.C:
				sharedStdinReader.Detach() // give control of stdin to bubbletea
				snippetsTimerIsOn = false
				snippet := ShowSnippetsWithReader(sharedStdinReader)
				sharedStdinReader.Attach()
				if snippet != "" {
					stdin.Write([]byte(snippet))
				}
			case data, ok := <-sharedStdinReader.Ch:
				// User typed in some more input after pressing '/' and before
				// the snippets timer is triggered.
				if !ok {
					return
				}
				snippetsTimer.Stop()
				snippetsTimerIsOn = false
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
			case data, ok := <-sharedStdinReader.Ch:
				if !ok {
					return
				}
				if data[0] == '/' &&
					len(data) == 1 &&
					fetchedSnippets != nil &&
					connectedToPrompt.Load() {
					// Activate snippets timer
					snippetsTimerIsOn = true
					snippetsTimer = time.NewTimer(snippetsTriggerTime)
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
