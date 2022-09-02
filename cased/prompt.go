package cased

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/gorilla/websocket"
)

type Prompt struct {
	Hostname                  string                 `json:"hostname"`
	Port                      string                 `json:"port"`
	Username                  string                 `json:"username"`
	IpAddress                 string                 `json:"ip_address"`
	Name                      string                 `json:"name"`
	Descript                  string                 `json:"description"`
	JumpCommand               string                 `json:"jump_command"`
	ShellCommand              string                 `json:"shell_command"`
	PreDownloadCommand        string                 `json:"pre_download_command"`
	Kind                      string                 `json:"kind"`
	Provider                  string                 `json:"provider"`
	Labels                    map[string]interface{} `json:"labels"`
	Principals                []string               `json:"principals"`
	Featured                  bool                   `json:"featured"`
	PromptForKey              bool                   `json:"prompt_for_key"`
	PromptForUsername         bool                   `json:"prompt_for_username"`
	CloseTerminalOnExit       bool                   `json:"close_terminal_on_exit"`
	Path                      string                 `json:"path"`
	NeedsMoreInfo             bool                   `json:"needs_more_info"`
	CertificateAuthentication bool                   `json:"certificate_authentication"`
	// "annotations": {},
	// "proxy_jump_selector": {},
}

// Map json response from cased-shell /api/prompts.
// { "data": [{"name": "prompt_name" ...} ...] }
type promptData struct {
	Data []Prompt `json:"data"`
}

// Data wrapped into a tea.Msg object.
type PromptsUpdateMsg struct {
	Prompts []Prompt
}

type PromptConnectedMsg struct {
	Conn *websocket.Conn
}

// Functions used by bubbles list component to display the items.
func (p Prompt) Title() string       { return p.Name }
func (p Prompt) Description() string { return p.Descript }
func (p Prompt) FilterValue() string { return p.Name }

// FetchPrompts fetches all prompts available from the cased shell,
// then wraps the results into a PromptsMessage object delivered to
// the bubbletea Update() function.
func FetchPrompts() tea.Msg {
	response, _, err := GET("/v2/api/prompts", nil)
	if err != nil {
		return ErrMsg{err}
	}

	var prompts promptData
	err = json.Unmarshal([]byte(response), &prompts)
	if err != nil {
		return ErrMsg{err}
	}

	return PromptsUpdateMsg{prompts.Data}
}

// Connect opens a new ssh session (over websocket) to the prompt passed as argument.
func ConnectToPrompt(p *Prompt) tea.Msg {
	params, err := SerializeParams(p)

	response, _, err := POST("/v2/", params)
	if err != nil {
		return ErrMsg{err}
	}

	var resp_map map[string]interface{}
	json.Unmarshal([]byte(response), &resp_map)
	if id, ok := resp_map["id"]; ok && id != nil {
		return openWebSocketConnection(id.(string))
	}

	if msg, ok := resp_map["status"]; ok {
		return ErrMsg{errors.New(msg.(string))}
	}

	return ErrMsg{errors.New("Authentication Failed")}
}

func openWebSocketConnection(id string) tea.Msg {
	cased_host := os.Getenv("CASED_SHELL_HOSTNAME")

	target_ws := "ws://" + cased_host + "/v2/ws?id=" + id

	header := http.Header{}
	cookie := CreateCookie()
	header.Set("Cookie", cookie)

	c, _, err := websocket.DefaultDialer.Dial(target_ws, header)

	if err != nil {
		return ErrMsg{err}
	}

	return PromptConnectedMsg{c}
}
