package cmd

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/containerd/console"
	"github.com/spf13/cobra"
)

var (
	termWidth  = 80
	termHeight = 25

	inactiveTabBorder = tabBorderWithBottom("┴", "─", "┴")
	activeTabBorder   = tabBorderWithBottom("┘", " ", "└")
	docStyle          = lipgloss.NewStyle().Padding(1, 2, 1, 2)
	highlightColor    = lipgloss.AdaptiveColor{Light: "#874BFD", Dark: "#7D56F4"}
	inactiveTabStyle  = lipgloss.NewStyle().Border(inactiveTabBorder, true).BorderForeground(highlightColor).Padding(0, 1)
	activeTabStyle    = inactiveTabStyle.Copy().Border(activeTabBorder, true)
	windowStyle       = lipgloss.NewStyle().BorderForeground(highlightColor).Padding(2, 0).Align(lipgloss.Center).Border(lipgloss.NormalBorder()).UnsetBorderTop()
)

// A snippet has a title and an associated command
type snippet struct {
	title string
	cmd   string
}

// The collection of all snippets are represented internally by this data structure
type snippets struct {
	categories []string
	items      [][]snippet
}

// Implementation of list.Model interface
func (s snippet) Title() string       { return s.title }
func (s snippet) Description() string { return s.cmd }
func (s snippet) FilterValue() string { return s.title }

// Used to display a list of available snippet categories
// when Tabs don't fit in the screen.
type snippetCategory struct {
	title string
}

func (s snippetCategory) Title() string       { return s.title }
func (s snippetCategory) Description() string { return "" }
func (s snippetCategory) FilterValue() string { return s.title }

type screen int

// Track current screen in the UI
const (
	// Screen showing the list of snippet categories (fallback screen when tabs don't fit in the terminal width)
	snippetCategoryScreen screen = iota
	// Screen showing a list of snippets from a selected category
	snippetScreen
)

type model struct {
	tabs      []string
	activeTab int
	snippets  []list.Model
	// The list below is used when Tabs don't fit horizontally on the screen
	// In that case we fallback to a list in order to display the snippets categories.
	snippetCategories list.Model
	selectedCategory  int
	currentScreen     screen
	smalScreen        bool // true when tabs don't fit in the screen
}

func init() {
	rootCmd.AddCommand(snippetsCmd)
}

var demoSnippets = snippets{
	// categories: []string{"Database", "Logs", "Server Management", "General"},
	categories: []string{"Database", "Logs", "Server Management", "General", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
	// categories: []string{"Database", "Logs"},
	items: [][]snippet{
		{
			{"Connect to PostgreSQL", "psql -U user -W <db>"},
			{"Connect to MySQL", "mysql -u user -p <db>"},
			{"Show active MySQL connections", "mysql ..."},
		},
		{
			{"Monitor apache logs", "tail -f /var/log/apache.log"},
			{"Monitor database logs", "tail -f /var/log/postgresql.log"},
			{"Check container log", "docker container logs -f <container>"},
		},
		{
			{"Restart docker", "sudo service docker restart"},
			{"Restart PostgreSQL", "sudo service postgresql restart"},
		},
		{
			{"Show active users", "who"},
			{"Show CPU stats", "vmstat"},
		},
		{}, // AAAAAAAAAAAAAAAAAAA....
	},
}

var selectedSnippet string

// promptsCmd represents the prompts command
var snippetsCmd = &cobra.Command{
	Use:     "snippets",
	Short:   "List available snippets",
	Example: "cased snippets",
	Run:     showSnippets,
}

var logFile *os.File

func showSnippets(cmd *cobra.Command, args []string) {
	fmt.Println(showSnippetsImpl())
}

func showSnippetsImpl() string {
	term := console.Current()
	termSize, _ := term.Size()

	if len(os.Getenv("DEBUG")) > 0 {
		logFile, err := tea.LogToFile("debug.log", "")
		if err != nil {
			log.Fatalln("DEBUG:", err)
		}
		defer logFile.Close()
	}

	// Keep track of initial terminal dimensions
	if termSize.Width > 0 {
		termWidth = int(termSize.Width)
	}
	if termSize.Height > 0 {
		termHeight = int(termSize.Height)
	}

	m := model{tabs: demoSnippets.categories, selectedCategory: -1}

	for i := range m.tabs {
		items := make([]list.Item, len(demoSnippets.items[i]))
		for k, v := range demoSnippets.items[i] {
			items[k] = snippet{title: v.title, cmd: v.cmd}
		}
		m.snippets = append(m.snippets, list.New(items, list.NewDefaultDelegate(), 0, 0))
		m.snippets[i].SetShowTitle(false)
		m.snippets[i].SetShowStatusBar(false)
		// m.snippets[i].SetShowHelp(false)
		// m.snippets[i].SetShowFilter(false)
		// m.snippets[i].SetShowPagination(false)
	}

	m.smalScreen = smallScreen(m)
	if m.smalScreen {
		m.currentScreen = snippetCategoryScreen
	}

	snippetCategories := make([]list.Item, len(demoSnippets.categories))
	for i, v := range demoSnippets.categories {
		snippetCategories[i] = snippetCategory{title: v}
	}
	m.snippetCategories = list.New(snippetCategories, list.NewDefaultDelegate(), 0, 0)
	m.snippetCategories.Title = "Select a snippet category"

	program := tea.NewProgram(m, tea.WithAltScreen())
	if err := program.Start(); err != nil {
		fmt.Println("Error running program:", err)
		os.Exit(1)
	}

	return selectedSnippet
}

func ShowSnippets() string {
	return showSnippetsImpl()
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) getCurrentList() *list.Model {
	if m.smalScreen {
		if m.currentScreen == snippetCategoryScreen {
			return &m.snippetCategories
		}
		return &m.snippets[m.selectedCategory]
	}

	return &m.snippets[m.activeTab]
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "q":
			if m.getCurrentList().FilterState() != list.Filtering {
				return m, tea.Quit
			}
		case "right", "tab":
			m.activeTab = min(m.activeTab+1, len(m.tabs)-1)
			return m, nil
		case "left", "shift+tab":
			m.activeTab = max(m.activeTab-1, 0)
			return m, nil
		case "enter":
			if m.getCurrentList() == &m.snippetCategories {
				m.selectedCategory = m.snippetCategories.Index()
				m.currentScreen = snippetScreen
			} else {
				snippet, ok := m.getCurrentList().SelectedItem().(snippet)
				if ok {
					selectedSnippet = snippet.cmd
					return m, tea.Quit
				}
			}
		}
	case tea.WindowSizeMsg:
		termWidth = msg.Width
		termHeight = msg.Height
		w, h := docStyle.GetFrameSize()
		m.smalScreen = smallScreen(m)

		if m.smalScreen {
			m.snippetCategories.SetSize(msg.Width-w-3, msg.Height-h-3)
		}

		for i := range m.snippets {
			m.snippets[i].SetSize(msg.Width-w-3, msg.Height-h-3)
		}

		log.Printf("WindowSize, w=%d, h=%d\n", termWidth, termHeight)
		log.Printf("DocSize, w=%d, h=%d\n", w, h)
		log.Printf("SmallScreen: %v\n", m.smalScreen)
	}

	var cmd tea.Cmd
	*(m.getCurrentList()), cmd = m.getCurrentList().Update(msg)

	return m, cmd
}

func (m model) View() string {
	if m.smalScreen {
		return m.getCurrentList().View()
	} else {
		tabs := drawTabs(m, true)
		doc := strings.Builder{}

		doc.WriteString(tabs)
		doc.WriteString("\n")
		// Render snippets from the active Tab
		// m.snippets[m.activeTab].SetSize(lipgloss.Width(tabs)-windowStyle.GetHorizontalFrameSize()-3, termHeight-lipgloss.Height(tabs)-5)
		w := lipgloss.Width(tabs) - windowStyle.GetHorizontalFrameSize()
		h := termHeight - lipgloss.Height(tabs) - windowStyle.GetVerticalFrameSize()
		m.getCurrentList().SetSize(w-2, h-2)
		// h := termHeight - lipgloss.Height(tabs) - windowStyle.GetVerticalFrameSize()

		doc.WriteString(
			windowStyle.Width(w).
				Render(lipgloss.JoinVertical(lipgloss.Center, m.snippets[m.activeTab].View())))
		return docStyle.Render(doc.String())
	}
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

func drawTabs(m model, fillScreen bool) string {
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
		} else if isLast {
			if isActive {
				border.BottomRight = "└"
			} else {
				border.BottomRight = "┴"
			}
		}
		style = style.Border(border)
		renderedTabs = append(renderedTabs, style.Render(t))
		if isLast && fillScreen {
			// Add an extra empty tab to fill the screen width
			finalTabW := lipgloss.Width(lipgloss.JoinHorizontal(lipgloss.Top, renderedTabs...))
			border.BottomLeft = "─"
			border.BottomRight = "┐"
			border.Bottom = "─"
			border.Top = " "
			border.TopLeft = " "
			border.TopRight = " "
			border.Left = " "
			border.Right = " "
			extraTabStyle := style.Border(border).Width(termWidth - finalTabW - windowStyle.GetHorizontalFrameSize() - 4)
			renderedTabs = append(renderedTabs, extraTabStyle.Render(""))
		}
	}

	return lipgloss.JoinHorizontal(lipgloss.Top, renderedTabs...)
}

// smallScreen reports whether the screen is too small for rendering the Tabs UI.
func smallScreen(m model) bool {
	log.Printf("smallScreen(), tabsize=%d, termw=%d\n", lipgloss.Width(drawTabs(m, false)), termWidth)
	return lipgloss.Width(drawTabs(m, false)) >= (termWidth - 3)
}
