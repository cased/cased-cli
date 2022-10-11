package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

var (
	defaultWidth = 20

	inactiveTabBorder = tabBorderWithBottom("┴", "─", "┴")
	activeTabBorder   = tabBorderWithBottom("┘", " ", "└")
	docStyle          = lipgloss.NewStyle().Padding(1, 2, 1, 2).Margin(1, 2)
	highlightColor    = lipgloss.AdaptiveColor{Light: "#874BFD", Dark: "#7D56F4"}
	inactiveTabStyle  = lipgloss.NewStyle().Border(inactiveTabBorder, true).BorderForeground(highlightColor).Padding(0, 1)
	activeTabStyle    = inactiveTabStyle.Copy().Border(activeTabBorder, true)
	windowStyle       = lipgloss.NewStyle().BorderForeground(highlightColor).Padding(2, 0).Align(lipgloss.Center).Border(lipgloss.NormalBorder()).UnsetBorderTop()
)

type item struct {
	title, desc string
}

func (i item) Title() string       { return i.title }
func (i item) Description() string { return i.desc }
func (i item) FilterValue() string { return i.title }

type model struct {
	tabs      []string
	activeTab int
	snippets  []list.Model
}

func init() {
	rootCmd.AddCommand(snippetsCmd)
}

type snippetElement struct {
	title string
	cmd   string
}

type snippets struct {
	sections []string
	items    [][]snippetElement
}

var demoSnippets = snippets{
	sections: []string{"Database", "Logs", "Server Management", "General"},
	items: [][]snippetElement{
		{
			{"Connect to PostgreSQL", "psql -U user -W <db>"},
			{"Connect to MySQL", "mysql -u user -p <db>"},
			{"Show active connections", "..."},
		},
		{
			{"Monitor apache logs", "tail -f /var/log/apache.log"},
			{"Monitor database logs", "tail -f /var/log/postgresql.log"},
		},
		{
			{"Restart docker", "sudo service docker restart"},
			{"Restart PostgreSQL", "sudo service postgresql restart"},
		},
		{
			{"Show active users", "who"},
			{"Show CPU stats", "vmstat"},
		},
	},
}

// promptsCmd represents the prompts command
var snippetsCmd = &cobra.Command{
	Use:     "snippets",
	Short:   "List available snippets",
	Example: "cased snippets",
	Run:     showSnippets,
}

func showSnippets(cmd *cobra.Command, args []string) {
	m := model{tabs: demoSnippets.sections}
	if err := tea.NewProgram(m).Start(); err != nil {
		fmt.Println("Error running program:", err)
		os.Exit(1)
	}

	for i, _ := range m.tabs {
		items := make([]list.Item, len(demoSnippets.items[i]))
		for k, v := range demoSnippets.items[i] {
			items[k] = item{title: v.title}
		}
		m.snippets = append(m.snippets, list.New(items, list.NewDefaultDelegate(), 0, 0))
		m.snippets[i].Title = demoSnippets.sections[i]
	}

	p := tea.NewProgram(m, tea.WithAltScreen())

	if err := p.Start(); err != nil {
		fmt.Println("ERROR")
		os.Exit(1)
	}
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch keypress := msg.String(); keypress {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "right", "l", "n", "tab":
			m.activeTab = min(m.activeTab+1, len(m.tabs)-1)
			return m, nil
		case "left", "h", "p", "shift+tab":
			m.activeTab = max(m.activeTab-1, 0)
			return m, nil
		}
	case tea.WindowSizeMsg:
		h, v := docStyle.GetFrameSize()
		for i, _ := range m.snippets {
			m.snippets[i].SetSize(msg.Width-h, msg.Height-v)
		}

	}

	var cmd tea.Cmd
	for i, _ := range m.snippets {
		m.snippets[i], cmd = m.snippets[i].Update(msg)
	}
	return m, cmd
}

func (m model) View() string {
	doc := strings.Builder{}

	var renderedTabs []string

	for i, t := range m.tabs {
		var style lipgloss.Style
		isFirst, isLast, isActive := i == 0, i == len(m.tabs)-1, i == m.activeTab
		if isActive {
			style = activeTabStyle.Copy()
		} else {
			style = inactiveTabStyle.Copy()
		}
		border, _, _, _, _ := style.GetBorder()
		if isFirst && isActive {
			border.BottomLeft = "│"
		} else if isFirst && !isActive {
			border.BottomLeft = "├"
		} else if isLast && isActive {
			border.BottomRight = "│"
		} else if isLast && !isActive {
			border.BottomRight = "┤"
		}
		style = style.Border(border)
		renderedTabs = append(renderedTabs, style.Render(t))
	}

	row := lipgloss.JoinHorizontal(lipgloss.Top, renderedTabs...)
	doc.WriteString(row)
	doc.WriteString("\n")
	// doc.WriteString(windowStyle.Width((lipgloss.Width(row) - windowStyle.GetHorizontalFrameSize())).Render(m.snippets[m.activeTab].View()))
	// m.snippets[0].View()
	return docStyle.Render(doc.String())
}

func tabBorderWithBottom(left, middle, right string) lipgloss.Border {
	border := lipgloss.RoundedBorder()
	border.BottomLeft = left
	border.Bottom = middle
	border.BottomRight = right
	return border
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
