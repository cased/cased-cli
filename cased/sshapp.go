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
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/gorilla/websocket"
	"github.com/muesli/termenv"

	"github.com/gliderlabs/ssh"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/wish"
	bm "github.com/charmbracelet/wish/bubbletea"
	lm "github.com/charmbracelet/wish/logging"
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

	buttonStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFF7DB")).
			Background(lipgloss.Color("#888B7E")).
			Padding(0, 3).
			MarginTop(1)

	activeButtonStyle = buttonStyle.Copy().
				Foreground(lipgloss.Color("#FFF7DB")).
				Background(lipgloss.Color("#F25D94")).
				MarginRight(2).
				Underline(true)
)

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
	Connected                  // Connected to a remote shell.
	ErrorState                 // Some error happened, a message dialog will be shown.
)

// Model used by our Tea app.
type model struct {
	term     string
	width    int
	height   int
	state    AppState
	err      error
	prompts  list.Model
	spinner  spinner.Model
	program  *tea.Program
	wsconn   *websocket.Conn
	wsbuffer bytes.Buffer
}

type SSHApp struct {
}

func (app *SSHApp) Start() {
	startSSHServer()
}

type websocketMsg struct {
	msg []byte
}

type websocketDisconnectedMsg struct{}

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

func (m *model) Init() tea.Cmd {
	return FetchPrompts
}

func (m *model) UpdatePrompts(prompts []Prompt) {
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
			h, v := docStyle.GetFrameSize()
			m.prompts.SetSize(msg.Width-h, msg.Height-v)
			if m.state == Connected {
				resizeMsg := fmt.Sprintf(`{"resize": [%d,%d]}`, msg.Width, msg.Height)
				m.wsconn.WriteMessage(websocket.TextMessage, []byte(resizeMsg))
			}
		}

	// Keypress event
	case tea.KeyMsg:
		if m.state == Connected {
			var wsmsg string
			if len(msg.Runes) > 0 {
				wsmsg = fmt.Sprintf(`{"data": %+q}`, string(msg.Runes))
			} else if msg.String() == "enter" {
				wsmsg = fmt.Sprint(`{"data": "\\r"}`)
			} else {
				wsmsg = fmt.Sprintf(`{"data": %q}`, msg.String())
			}
			fmt.Println("Sending:", wsmsg)
			m.wsconn.WriteMessage(websocket.TextMessage, []byte(wsmsg))
			return m, nil
		}

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
			case ErrorState:
				m.err = nil
				m.state = Navigating
			}
			return m, nil
		}

	case ErrMsg:
		m.err = msg
		m.state = ErrorState
		return m, nil

	// Handle response message from FetchPrompts()
	case PromptsUpdateMsg:
		m.UpdatePrompts(msg.Prompts)
		m.state = Navigating

	case PromptConnectedMsg:
		m.wsconn = msg.Conn
		m.state = Connected
		go websocketHandler(m)
		return m, nil

	case websocketDisconnectedMsg:
		m.state = Navigating
		return m, nil

	case websocketMsg:
		m.wsbuffer.Write(msg.msg)
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
		if m.wsbuffer.Len() > 0 {
			msg := m.wsbuffer.String()
			m.wsbuffer.Reset()
			return msg
		}

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
		m := &model{
			term:    pty.Term,
			width:   pty.Window.Width,
			height:  pty.Window.Height,
			state:   Fetching,
			spinner: spin,
		}
		program := tea.NewProgram(m, tea.WithInput(s), tea.WithOutput(s), tea.WithAltScreen())
		m.program = program
		fmt.Println("Tea program:", program, m.program)
		return program
	}
	return bm.MiddlewareWithProgramHandler(teaHandler, termenv.ANSI256)
}

func websocketHandler(m *model) {
	defer m.wsconn.Close()

	done := make(chan struct{})

	// Read websocket messages in a goroutine.
	go func() {
		defer close(done)
		for {
			_, message, err := m.wsconn.ReadMessage()
			if err != nil {
				m.program.Send(ErrMsg{err})
				return
			}

			// Triggers Update() function.\
			fmt.Println("message, program:", m.program)
			m.program.Send(websocketMsg{message})
		}
	}()

	<-done
	m.program.Send(websocketDisconnectedMsg{})
}
