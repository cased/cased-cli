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

package cased

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/wish"
	bm "github.com/charmbracelet/wish/bubbletea"
	lm "github.com/charmbracelet/wish/logging"
	"github.com/gliderlabs/ssh"
	"github.com/gorilla/websocket"
	"github.com/mattn/go-localereader"
	"github.com/muesli/cancelreader"
	"github.com/muesli/termenv"
)

// Styles.
var (
	subtle = lipgloss.AdaptiveColor{Light: "#D9DCCF", Dark: "#383838"}

	docStyle = lipgloss.NewStyle().Margin(1, 2)

	errorDialogBoxStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("#874BFD")).
				Padding(1, 0).
				BorderTop(true).
				BorderLeft(true).
				BorderRight(true).
				BorderBottom(true)
)

// Default settings
const (
	DefaultListenAddr = "0.0.0.0"
	DefaultListenPort = "6565"
)

type AppState int64

// App state machine.
const (
	Fetching   AppState = iota // Fetching prompt list.
	Navigating                 // Navigating UI.
	Connecting                 // Connecting to a prompt.
	Connected                  // Connected to a prompt.
	ErrorState                 // Some error happened, a message dialog will be shown.
)

// Model used by our Tea app.
type model struct {
	term   string
	width  int
	height int
	state  AppState
	// atomic to avoid using mutex to check state == Connected
	connnected atomic.Bool
	err        error
	prompts    list.Model
	spinner    spinner.Model
	program    *tea.Program
	wsconn     *websocket.Conn
}

// Wraps tea input reader.
type sshreader struct {
	r io.Reader
}

var (
	// When connected to a prompt, we use this channel to notify the casedShellMiddleware
	// that it can control the ssh sesssion (read from/write to the ssh.Session).
	// The bubbleTeaMiddleware is disabled during the webshell session.
	casedShellReady chan bool

	// Send websocket messages read from cased shell to this channel.
	casedShellMsgChan chan []byte

	// Messages read from the client ssh session are sent to this channel.
	sshMsgChan chan sshdata

	// A pointer to the model used by our app.
	casedModel *model

	// Fake bubbleteaMiddleware to read from this object.
	// We do so in order to handle input when we are connect to a prompt, in that
	// case we forward the data read to the cased websocket shell session instead
	// of forwarding input to the bubble tea app.
	sshReader *sshreader
)

type sshapp struct {
}

func NewSSHApp() *sshapp {
	return &sshapp{}
}

// sshdata stores a packet read from the client ssh session (sshReader).
type sshdata struct {
	p []byte // packet data
	n int    // packet length
}

func (r *sshreader) Read(p []byte) (n int, err error) {
	n, err = r.r.Read(p)
	if err != nil {
		return
	}
	if casedModel.connnected.Load() {
		sshMsgChan <- sshdata{p, n}
	}
	return
}

func (app *sshapp) Start() {
	casedShellReady = make(chan bool)
	casedShellMsgChan = make(chan []byte)
	sshMsgChan = make(chan sshdata)
	startSSHServer()
}

func startSSHServer() {
	host := os.Getenv("CASED_SSH_HOST")
	if host == "" {
		host = DefaultListenAddr
	}
	port := os.Getenv("CASED_SSH_PORT")
	if port == "" {
		port = DefaultListenPort
	}

	s, err := wish.NewServer(
		wish.WithAddress(fmt.Sprintf("%s:%s", host, port)),
		wish.WithHostKeyPath("/home/avenger/.ssh/id_rsa"),
		wish.WithPublicKeyAuth(func(ctx ssh.Context, key ssh.PublicKey) bool {
			return true
		}),
		wish.WithMiddleware(
			casedCustomBubbleteaMiddleware(),
			casedShellMiddleware(),
			lm.Middleware(),
		),
	)

	if err != nil {
		log.Fatalln(err)
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	log.Printf("Starting SSH server on %s:%s", host, port)
	go func() {
		if err = s.ListenAndServe(); err != nil {
			log.Fatalln(err)
		}
	}()

	<-done
	log.Println("Stopping SSH server")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer func() { cancel() }()
	if err := s.Shutdown(ctx); err != nil {
		log.Fatalln(err)
	}
}

// Init starts the bubbletea app, we return a tea.Cmd that will
// fetch the prompts from cased shell in the background.
func (m *model) Init() tea.Cmd {
	return FetchPrompts
}

// updatePrompts creates a list with the prompts returned from FetchPrompts.
func (m *model) updatePrompts(prompts []Prompt) {
	items := make([]list.Item, len(prompts))
	for i, prompt := range prompts {
		items[i] = prompt
	}
	m.prompts = list.New(items, list.NewDefaultDelegate(), 0, 0)
	m.prompts.Title = "Available Prompts"
	h, v := docStyle.GetFrameSize()
	m.prompts.SetSize(m.width-h, m.height-v)
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	// Terminal resize
	case tea.WindowSizeMsg:
		m.height = msg.Height
		m.width = msg.Width
		if m.state != Fetching {
			// Update list size
			h, v := docStyle.GetFrameSize()
			m.prompts.SetSize(msg.Width-h, msg.Height-v)
		}

	// Keypress event
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "enter":
			switch m.state {
			case Navigating:
				p, ok := m.prompts.SelectedItem().(Prompt)
				if ok {
					m.state = Connecting
					return m, func() tea.Msg {
						return ConnectToPrompt(&p)
					}
				}
			// <ENTER> Closes the error popup window.
			case ErrorState:
				m.err = nil
				m.state = Navigating
			}
			return m, nil
		}

	// Show an error dialog on the screen with a message describing it.
	case ErrMsg:
		m.err = msg
		m.state = ErrorState
		return m, nil

	// Handle response message from FetchPrompts()
	case PromptsUpdateMsg:
		m.updatePrompts(msg.Prompts)
		m.state = Navigating

	case PromptConnectedMsg:
		m.wsconn = msg.Conn
		m.connnected.Store(true)
		m.state = Connected
		// Handle websocket messages in a separate goroutine.
		go websocketHandler(m)
		return m, nil

	// Update spinner (if still fetching prompts)
	case spinner.TickMsg:
		if m.state == Fetching {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			return m, cmd
		}
	}

	if m.state == Fetching {
		// Bootstrap spinner
		return m, m.spinner.Tick
	}

	if m.state == Navigating {
		var cmd tea.Cmd
		m.prompts, cmd = m.prompts.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m *model) View() string {
	switch m.state {
	case Connected:
		return ""
	case Fetching:
		return fmt.Sprintf("%s Fetching prompts...\n", m.spinner.View())

	case Connecting:
		p, ok := m.prompts.SelectedItem().(Prompt)
		prompt_name := ""
		if ok {
			prompt_name = " (" + p.Name + ")"
		}
		return fmt.Sprintf("%s Connecting to prompt%s...\n", m.spinner.View(), prompt_name)

	case ErrorState:
		msg := lipgloss.NewStyle().Width(50).Align(lipgloss.Center).Render(m.err.Error())
		confirm := lipgloss.NewStyle().Width(50).Align(lipgloss.Center).Render("Press <ENTER> to return to the main screen.")
		ui := lipgloss.JoinVertical(lipgloss.Center, msg, "\n", confirm)

		dialog := lipgloss.Place(m.width, 9,
			lipgloss.Center, lipgloss.Center,
			errorDialogBoxStyle.Render(ui),
			// lipgloss.WithWhitespaceChars("░"),
			lipgloss.WithWhitespaceForeground(subtle),
		)

		return docStyle.Render(dialog)

	default:
		// Render our list of prompts.
		return docStyle.Render(m.prompts.View())
	}
}

func casedCustomBubbleteaMiddleware() wish.Middleware {
	teaHandler := func(s ssh.Session) *tea.Program {
		pty, _, active := s.Pty()
		if !active {
			wish.Fatalln(s, "no active terminal, skipping")
			return nil
		}

		spin := spinner.New()
		spin.Spinner = spinner.Dot
		spin.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))
		casedModel = &model{
			term:    pty.Term,
			width:   pty.Window.Width,
			height:  pty.Window.Height,
			state:   Fetching,
			spinner: spin,
		}
		sshReader = &sshreader{s}
		program := tea.NewProgram(casedModel, tea.WithInput(sshReader), tea.WithOutput(s), tea.WithAltScreen())
		casedModel.program = program
		return program
	}
	return bm.MiddlewareWithProgramHandler(teaHandler, termenv.ANSI256)
}

// casedShellMiddleware keeps reading input from client ssh session and
// forwarding the data to the websocket shell connection.
func casedShellMiddleware() wish.Middleware {
	return func(h ssh.Handler) ssh.Handler {
		return func(s ssh.Session) {
			// Forward remote websocket messages received to the ssh client.
			go func() {
				for {
					select {
					case <-s.Context().Done():
						return
					case msg := <-casedShellMsgChan:
						s.Write(msg)
					}
				}
			}()

			// Forwards messages from the ssh client session read from
			// the bubbleteaMiddleware to the websocket shell.
			go func() {
				for {
					select {
					case pkg := <-sshMsgChan:
						sendWSMessage(pkg.p[:pkg.n])
					}
				}
			}()

			// Forward messages from the ssh client session read from this middleware
			// to the websocket shell.
			go func() {
				buffer := make([]byte, 32)
				_, windowChanges, _ := s.Pty()
				for {
					select {
					case <-s.Context().Done():
						return

					// Blocks until we successfully connect to a prompt.
					case <-casedShellReady:
					ReadLoop:
						for {
							select {
							// Client ssh session disconnected.
							case <-s.Context().Done():
								return

							// Handle window resize.
							case w := <-windowChanges:
								if casedModel.connnected.Load() {
									resizeMsg := fmt.Sprintf(`{"resize": [%d,%d]}`, w.Width, w.Height)
									err := casedModel.wsconn.WriteMessage(websocket.TextMessage, []byte(resizeMsg))
									if err != nil {
										break ReadLoop
									}
								} else {
									break ReadLoop

								}
							default:
								// We disconnected from websocket shell, break the read loop.
								if !casedModel.connnected.Load() {
									break ReadLoop
								}

								// Read data from client ssh session.
								n, err := s.Read(buffer)
								if err != nil {
									return
								}

								// fmt.Printf("read %d: %v, %+q\n", n, buffer[:n], buffer[:n])
								if casedModel.connnected.Load() {
									if err := sendWSMessage(buffer[:n]); err != nil {
										break ReadLoop
									}
								} else {
									// We got some data but disconnected from the websocket shell.
									// In this case we forward the data back to the bubbleTeaMiddleware.
									msgs, err := readInputs(bytes.NewReader(buffer[:n]))
									if err != nil {
										if !errors.Is(err, io.EOF) && !errors.Is(err, cancelreader.ErrCanceled) {
										}

										return
									}

									// Send input keys (as tea.KeyMsg) to the bubble tea app.
									for _, msg := range msgs {
										casedModel.program.Send(msg)
									}

									break ReadLoop
								}
							}
						}
					}
				}

			}()

			h(s) // call previous handler in the chain.
		}
	}
}

// sendWSMessage encodes the message to the proper format expected
// by cased shell / paramiko, them send it over the websocket channel.
func sendWSMessage(msg []byte) error {
	var b bytes.Buffer

	msg = bytes.Replace(msg, []byte("\""), []byte(`\"`), -1)
	msg = bytes.Replace(msg, []byte("\r"), []byte("\\r"), -1)
	msg = bytes.Replace(msg, []byte("\n"), []byte("\\r"), -1)
	msg = bytes.Replace(msg, []byte("\x1b[1~"), []byte("\x1b[H"), -1) // <HOME>
	msg = bytes.Replace(msg, []byte("\x1b[7~"), []byte("\x1b[H"), -1) // <HOME> urxvt
	msg = bytes.Replace(msg, []byte("\x1b[4~"), []byte("\x1b[F"), -1) // <END>
	msg = bytes.Replace(msg, []byte("\x1b[8~"), []byte("\x1b[F"), -1) // <END> urxvt

	for len(msg) > 0 {
		r, size := utf8.DecodeRune(msg)

		if r > unicode.MaxLatin1 {
			if size > 3 {
				r1, r2 := utf16.EncodeRune(r)
				b.WriteString(fmt.Sprintf("\\u%04x\\u%04x", r1, r2))
			} else {
				b.WriteString(fmt.Sprintf("\\u%04x", r))
			}

		} else if unicode.IsControl(r) {
			b.WriteString(fmt.Sprintf("\\u%04x", r))
		} else {
			b.WriteRune(r)
		}

		msg = msg[size:]
	}

	wsmsg := []byte(`{"data": "`)
	wsmsg = append(wsmsg, b.Bytes()...)
	wsmsg = append(wsmsg, []byte(`"}`)...)
	return casedModel.wsconn.WriteMessage(websocket.TextMessage, []byte(wsmsg))
}

// websocketHandler reads message from the websocket connection and
// sends them to the casedShellMsgChan channel, the casedShellMiddleware
// then forward the messages read from the channel to the ssh session.
func websocketHandler(m *model) {
	defer m.wsconn.Close()

	if err := m.program.ReleaseTerminal(); err != nil {
		m.program.Send(ErrMsg{err})
		return
	}

	casedShellReady <- true

	for {
		_, message, err := m.wsconn.ReadMessage()
		if err != nil {
			m.state = Navigating
			m.program.RestoreTerminal()
			m.connnected.Store(false)
			m.program.Send(ErrMsg{err})
			return
		}

		casedShellMsgChan <- message
	}
}

/**************************************************************
 * ALL CODE THAT FOLLOWS WAS EXTRACTED FROM bubbleTea project *
 **************************************************************/

// readInputs reads keypress and mouse inputs from a TTY and returns messages
// containing information about the key or mouse events accordingly.
func readInputs(input io.Reader) ([]tea.Msg, error) {
	var buf [256]byte

	// Read and block
	numBytes, err := input.Read(buf[:])
	if err != nil {
		return nil, err
	}
	b := buf[:numBytes]
	b, err = localereader.UTF8(b)
	if err != nil {
		return nil, err
	}

	// Check if it's a mouse event. For now we're parsing X10-type mouse events
	// only.
	mouseEvent, err := parseX10MouseEvents(b)
	if err == nil {
		var m []tea.Msg
		for _, v := range mouseEvent {
			m = append(m, tea.MouseMsg(v))
		}
		return m, nil
	}

	var runeSets [][]rune
	var runes []rune

	// Translate input into runes. In most cases we'll receive exactly one
	// rune, but there are cases, particularly when an input method editor is
	// used, where we can receive multiple runes at once.
	for i, w := 0, 0; i < len(b); i += w {
		r, width := utf8.DecodeRune(b[i:])
		if r == utf8.RuneError {
			return nil, errors.New("could not decode rune")
		}

		if r == '\x1b' && len(runes) > 1 {
			// a new key sequence has started
			runeSets = append(runeSets, runes)
			runes = []rune{}
		}

		runes = append(runes, r)
		w = width
	}
	// add the final set of runes we decoded
	runeSets = append(runeSets, runes)

	if len(runeSets) == 0 {
		return nil, errors.New("received 0 runes from input")
	}

	var msgs []tea.Msg
	for _, runes := range runeSets {
		// Is it a sequence, like an arrow key?
		if k, ok := sequences[string(runes)]; ok {
			msgs = append(msgs, tea.KeyMsg(k))
			continue
		}

		// Some of these need special handling.
		hex := fmt.Sprintf("%x", runes)
		if k, ok := hexes[hex]; ok {
			msgs = append(msgs, tea.KeyMsg(k))
			continue
		}

		// Is the alt key pressed? If so, the buffer will be prefixed with an
		// escape.
		if len(runes) > 1 && runes[0] == 0x1b {
			msgs = append(msgs, tea.KeyMsg(tea.Key{Alt: true, Type: tea.KeyRunes, Runes: runes[1:]}))
			continue
		}

		for _, v := range runes {
			// Is the first rune a control character?
			r := tea.KeyType(v)
			if r <= keyUS || r == keyDEL {
				msgs = append(msgs, tea.KeyMsg(tea.Key{Type: r}))
				continue
			}

			// If it's a space, override the type with KeySpace (but still include
			// the rune).
			if r == ' ' {
				msgs = append(msgs, tea.KeyMsg(tea.Key{Type: tea.KeySpace, Runes: []rune{v}}))
				continue
			}

			// Welp, just regular, ol' runes.
			msgs = append(msgs, tea.KeyMsg(tea.Key{Type: tea.KeyRunes, Runes: []rune{v}}))
		}
	}

	return msgs, nil
}

// Parse X10-encoded mouse events; the simplest kind. The last release of X10
// was December 1986, by the way.
//
// X10 mouse events look like:
//
//	ESC [M Cb Cx Cy
//
// See: http://www.xfree86.org/current/ctlseqs.html#Mouse%20Tracking
func parseX10MouseEvents(buf []byte) ([]tea.MouseEvent, error) {
	var r []tea.MouseEvent

	seq := []byte("\x1b[M")
	if !bytes.Contains(buf, seq) {
		return r, errors.New("not an X10 mouse event")
	}

	for _, v := range bytes.Split(buf, seq) {
		if len(v) == 0 {
			continue
		}
		if len(v) != 3 {
			return r, errors.New("not an X10 mouse event")
		}

		var m tea.MouseEvent
		const byteOffset = 32
		e := v[0] - byteOffset

		const (
			bitShift  = 0b0000_0100
			bitAlt    = 0b0000_1000
			bitCtrl   = 0b0001_0000
			bitMotion = 0b0010_0000
			bitWheel  = 0b0100_0000

			bitsMask = 0b0000_0011

			bitsLeft    = 0b0000_0000
			bitsMiddle  = 0b0000_0001
			bitsRight   = 0b0000_0010
			bitsRelease = 0b0000_0011

			bitsWheelUp   = 0b0000_0000
			bitsWheelDown = 0b0000_0001
		)

		if e&bitWheel != 0 {
			// Check the low two bits.
			switch e & bitsMask {
			case bitsWheelUp:
				m.Type = tea.MouseWheelUp
			case bitsWheelDown:
				m.Type = tea.MouseWheelDown
			}
		} else {
			// Check the low two bits.
			// We do not separate clicking and dragging.
			switch e & bitsMask {
			case bitsLeft:
				m.Type = tea.MouseLeft
			case bitsMiddle:
				m.Type = tea.MouseMiddle
			case bitsRight:
				m.Type = tea.MouseRight
			case bitsRelease:
				if e&bitMotion != 0 {
					m.Type = tea.MouseMotion
				} else {
					m.Type = tea.MouseRelease
				}
			}
		}

		if e&bitAlt != 0 {
			m.Alt = true
		}
		if e&bitCtrl != 0 {
			m.Ctrl = true
		}

		// (1,1) is the upper left. We subtract 1 to normalize it to (0,0).
		m.X = int(v[1]) - byteOffset - 1
		m.Y = int(v[2]) - byteOffset - 1

		r = append(r, m)
	}

	return r, nil
}

// Sequence mappings.
var sequences = map[string]tea.Key{
	// Arrow keys
	"\x1b[A":     {Type: tea.KeyUp},
	"\x1b[B":     {Type: tea.KeyDown},
	"\x1b[C":     {Type: tea.KeyRight},
	"\x1b[D":     {Type: tea.KeyLeft},
	"\x1b[1;2A":  {Type: tea.KeyShiftUp},
	"\x1b[1;2B":  {Type: tea.KeyShiftDown},
	"\x1b[1;2C":  {Type: tea.KeyShiftRight},
	"\x1b[1;2D":  {Type: tea.KeyShiftLeft},
	"\x1b[OA":    {Type: tea.KeyShiftUp},    // DECCKM
	"\x1b[OB":    {Type: tea.KeyShiftDown},  // DECCKM
	"\x1b[OC":    {Type: tea.KeyShiftRight}, // DECCKM
	"\x1b[OD":    {Type: tea.KeyShiftLeft},  // DECCKM
	"\x1b[a":     {Type: tea.KeyShiftUp},    // urxvt
	"\x1b[b":     {Type: tea.KeyShiftDown},  // urxvt
	"\x1b[c":     {Type: tea.KeyShiftRight}, // urxvt
	"\x1b[d":     {Type: tea.KeyShiftLeft},  // urxvt
	"\x1b[1;3A":  {Type: tea.KeyUp, Alt: true},
	"\x1b[1;3B":  {Type: tea.KeyDown, Alt: true},
	"\x1b[1;3C":  {Type: tea.KeyRight, Alt: true},
	"\x1b[1;3D":  {Type: tea.KeyLeft, Alt: true},
	"\x1b\x1b[A": {Type: tea.KeyUp, Alt: true},    // urxvt
	"\x1b\x1b[B": {Type: tea.KeyDown, Alt: true},  // urxvt
	"\x1b\x1b[C": {Type: tea.KeyRight, Alt: true}, // urxvt
	"\x1b\x1b[D": {Type: tea.KeyLeft, Alt: true},  // urxvt
	"\x1b[1;4A":  {Type: tea.KeyShiftUp, Alt: true},
	"\x1b[1;4B":  {Type: tea.KeyShiftDown, Alt: true},
	"\x1b[1;4C":  {Type: tea.KeyShiftRight, Alt: true},
	"\x1b[1;4D":  {Type: tea.KeyShiftLeft, Alt: true},
	"\x1b\x1b[a": {Type: tea.KeyShiftUp, Alt: true},    // urxvt
	"\x1b\x1b[b": {Type: tea.KeyShiftDown, Alt: true},  // urxvt
	"\x1b\x1b[c": {Type: tea.KeyShiftRight, Alt: true}, // urxvt
	"\x1b\x1b[d": {Type: tea.KeyShiftLeft, Alt: true},  // urxvt
	"\x1b[1;5A":  {Type: tea.KeyCtrlUp},
	"\x1b[1;5B":  {Type: tea.KeyCtrlDown},
	"\x1b[1;5C":  {Type: tea.KeyCtrlRight},
	"\x1b[1;5D":  {Type: tea.KeyCtrlLeft},
	"\x1b[Oa":    {Type: tea.KeyCtrlUp, Alt: true},    // urxvt
	"\x1b[Ob":    {Type: tea.KeyCtrlDown, Alt: true},  // urxvt
	"\x1b[Oc":    {Type: tea.KeyCtrlRight, Alt: true}, // urxvt
	"\x1b[Od":    {Type: tea.KeyCtrlLeft, Alt: true},  // urxvt
	"\x1b[1;6A":  {Type: tea.KeyCtrlShiftUp},
	"\x1b[1;6B":  {Type: tea.KeyCtrlShiftDown},
	"\x1b[1;6C":  {Type: tea.KeyCtrlShiftRight},
	"\x1b[1;6D":  {Type: tea.KeyCtrlShiftLeft},
	"\x1b[1;7A":  {Type: tea.KeyCtrlUp, Alt: true},
	"\x1b[1;7B":  {Type: tea.KeyCtrlDown, Alt: true},
	"\x1b[1;7C":  {Type: tea.KeyCtrlRight, Alt: true},
	"\x1b[1;7D":  {Type: tea.KeyCtrlLeft, Alt: true},
	"\x1b[1;8A":  {Type: tea.KeyCtrlShiftUp, Alt: true},
	"\x1b[1;8B":  {Type: tea.KeyCtrlShiftDown, Alt: true},
	"\x1b[1;8C":  {Type: tea.KeyCtrlShiftRight, Alt: true},
	"\x1b[1;8D":  {Type: tea.KeyCtrlShiftLeft, Alt: true},

	// Miscellaneous keys
	"\x1b[Z":      {Type: tea.KeyShiftTab},
	"\x1b[3~":     {Type: tea.KeyDelete},
	"\x1b[3;3~":   {Type: tea.KeyDelete, Alt: true},
	"\x1b[1~":     {Type: tea.KeyHome},
	"\x1b[1;3H~":  {Type: tea.KeyHome, Alt: true},
	"\x1b[4~":     {Type: tea.KeyEnd},
	"\x1b[1;3F~":  {Type: tea.KeyEnd, Alt: true},
	"\x1b[5~":     {Type: tea.KeyPgUp},
	"\x1b[5;3~":   {Type: tea.KeyPgUp, Alt: true},
	"\x1b[6~":     {Type: tea.KeyPgDown},
	"\x1b[6;3~":   {Type: tea.KeyPgDown, Alt: true},
	"\x1b[7~":     {Type: tea.KeyHome},              // urxvt
	"\x1b[8~":     {Type: tea.KeyEnd},               // urxvt
	"\x1b\x1b[3~": {Type: tea.KeyDelete, Alt: true}, // urxvt
	"\x1b\x1b[5~": {Type: tea.KeyPgUp, Alt: true},   // urxvt
	"\x1b\x1b[6~": {Type: tea.KeyPgDown, Alt: true}, // urxvt
	"\x1b\x1b[7~": {Type: tea.KeyHome, Alt: true},   // urxvt
	"\x1b\x1b[8~": {Type: tea.KeyEnd, Alt: true},    // urxvt

	// Function keys, X11
	"\x1bOP":     {Type: tea.KeyF1},  // vt100
	"\x1bOQ":     {Type: tea.KeyF2},  // vt100
	"\x1bOR":     {Type: tea.KeyF3},  // vt100
	"\x1bOS":     {Type: tea.KeyF4},  // vt100
	"\x1b[15~":   {Type: tea.KeyF5},  // also urxvt
	"\x1b[17~":   {Type: tea.KeyF6},  // also urxvt
	"\x1b[18~":   {Type: tea.KeyF7},  // also urxvt
	"\x1b[19~":   {Type: tea.KeyF8},  // also urxvt
	"\x1b[20~":   {Type: tea.KeyF9},  // also urxvt
	"\x1b[21~":   {Type: tea.KeyF10}, // also urxvt
	"\x1b[23~":   {Type: tea.KeyF11}, // also urxvt
	"\x1b[24~":   {Type: tea.KeyF12}, // also urxvt
	"\x1b[1;2P":  {Type: tea.KeyF13},
	"\x1b[1;2Q":  {Type: tea.KeyF14},
	"\x1b[1;2R":  {Type: tea.KeyF15},
	"\x1b[1;2S":  {Type: tea.KeyF16},
	"\x1b[15;2~": {Type: tea.KeyF17},
	"\x1b[17;2~": {Type: tea.KeyF18},
	"\x1b[18;2~": {Type: tea.KeyF19},
	"\x1b[19;2~": {Type: tea.KeyF20},

	// Function keys with the alt modifier, X11
	"\x1b[1;3P":  {Type: tea.KeyF1, Alt: true},
	"\x1b[1;3Q":  {Type: tea.KeyF2, Alt: true},
	"\x1b[1;3R":  {Type: tea.KeyF3, Alt: true},
	"\x1b[1;3S":  {Type: tea.KeyF4, Alt: true},
	"\x1b[15;3~": {Type: tea.KeyF5, Alt: true},
	"\x1b[17;3~": {Type: tea.KeyF6, Alt: true},
	"\x1b[18;3~": {Type: tea.KeyF7, Alt: true},
	"\x1b[19;3~": {Type: tea.KeyF8, Alt: true},
	"\x1b[20;3~": {Type: tea.KeyF9, Alt: true},
	"\x1b[21;3~": {Type: tea.KeyF10, Alt: true},
	"\x1b[23;3~": {Type: tea.KeyF11, Alt: true},
	"\x1b[24;3~": {Type: tea.KeyF12, Alt: true},

	// Function keys, urxvt
	"\x1b[11~": {Type: tea.KeyF1},
	"\x1b[12~": {Type: tea.KeyF2},
	"\x1b[13~": {Type: tea.KeyF3},
	"\x1b[14~": {Type: tea.KeyF4},
	"\x1b[25~": {Type: tea.KeyF13},
	"\x1b[26~": {Type: tea.KeyF14},
	"\x1b[28~": {Type: tea.KeyF15},
	"\x1b[29~": {Type: tea.KeyF16},
	"\x1b[31~": {Type: tea.KeyF17},
	"\x1b[32~": {Type: tea.KeyF18},
	"\x1b[33~": {Type: tea.KeyF19},
	"\x1b[34~": {Type: tea.KeyF20},

	// Function keys with the alt modifier, urxvt
	"\x1b\x1b[11~": {Type: tea.KeyF1, Alt: true},
	"\x1b\x1b[12~": {Type: tea.KeyF2, Alt: true},
	"\x1b\x1b[13~": {Type: tea.KeyF3, Alt: true},
	"\x1b\x1b[14~": {Type: tea.KeyF4, Alt: true},
	"\x1b\x1b[25~": {Type: tea.KeyF13, Alt: true},
	"\x1b\x1b[26~": {Type: tea.KeyF14, Alt: true},
	"\x1b\x1b[28~": {Type: tea.KeyF15, Alt: true},
	"\x1b\x1b[29~": {Type: tea.KeyF16, Alt: true},
	"\x1b\x1b[31~": {Type: tea.KeyF17, Alt: true},
	"\x1b\x1b[32~": {Type: tea.KeyF18, Alt: true},
	"\x1b\x1b[33~": {Type: tea.KeyF19, Alt: true},
	"\x1b\x1b[34~": {Type: tea.KeyF20, Alt: true},
}

// Hex code mappings.
var hexes = map[string]tea.Key{
	"1b0d": {Type: tea.KeyEnter, Alt: true},
	"1b7f": {Type: tea.KeyBackspace, Alt: true},

	// Powershell
	"1b4f41": {Type: tea.KeyUp, Alt: false},
	"1b4f42": {Type: tea.KeyDown, Alt: false},
	"1b4f43": {Type: tea.KeyRight, Alt: false},
	"1b4f44": {Type: tea.KeyLeft, Alt: false},
}

const (
	keyNUL tea.KeyType = 0   // null, \0
	keySOH tea.KeyType = 1   // start of heading
	keySTX tea.KeyType = 2   // start of text
	keyETX tea.KeyType = 3   // break, ctrl+c
	keyEOT tea.KeyType = 4   // end of transmission
	keyENQ tea.KeyType = 5   // enquiry
	keyACK tea.KeyType = 6   // acknowledge
	keyBEL tea.KeyType = 7   // bell, \a
	keyBS  tea.KeyType = 8   // backspace
	keyHT  tea.KeyType = 9   // horizontal tabulation, \t
	keyLF  tea.KeyType = 10  // line feed, \n
	keyVT  tea.KeyType = 11  // vertical tabulation \v
	keyFF  tea.KeyType = 12  // form feed \f
	keyCR  tea.KeyType = 13  // carriage return, \r
	keySO  tea.KeyType = 14  // shift out
	keySI  tea.KeyType = 15  // shift in
	keyDLE tea.KeyType = 16  // data link escape
	keyDC1 tea.KeyType = 17  // device control one
	keyDC2 tea.KeyType = 18  // device control two
	keyDC3 tea.KeyType = 19  // device control three
	keyDC4 tea.KeyType = 20  // device control four
	keyNAK tea.KeyType = 21  // negative acknowledge
	keySYN tea.KeyType = 22  // synchronous idle
	keyETB tea.KeyType = 23  // end of transmission block
	keyCAN tea.KeyType = 24  // cancel
	keyEM  tea.KeyType = 25  // end of medium
	keySUB tea.KeyType = 26  // substitution
	keyESC tea.KeyType = 27  // escape, \e
	keyFS  tea.KeyType = 28  // file separator
	keyGS  tea.KeyType = 29  // group separator
	keyRS  tea.KeyType = 30  // record separator
	keyUS  tea.KeyType = 31  // unit separator
	keyDEL tea.KeyType = 127 // delete. on most systems this is mapped to backspace, I hear
)
