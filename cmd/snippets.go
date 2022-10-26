package cmd

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/containerd/console"
	"github.com/spf13/cobra"
)

const (
	darkGray = lipgloss.Color("#767676")
)

var (
	termWidth          = 80
	termHeight         = 25
	snippetRegex       = regexp.MustCompile(`\{\{[^}]+\}\}`) // matches {{string}}
	snippetFilterRegex = regexp.MustCompile(`\{\{|\}\}`)     // removes the {{ and }} from the string

	inactiveTabBorder = tabBorderWithBottom("┴", "─", "┴")
	activeTabBorder   = tabBorderWithBottom("┘", " ", "└")
	docStyle          = lipgloss.NewStyle().Padding(1, 2, 1, 2)
	highlightColor    = lipgloss.AdaptiveColor{Light: "#874BFD", Dark: "#7D56F4"}
	inactiveTabStyle  = lipgloss.NewStyle().Border(inactiveTabBorder, true).BorderForeground(highlightColor).Padding(0, 1)
	activeTabStyle    = inactiveTabStyle.Copy().Border(activeTabBorder, true)
	windowStyle       = lipgloss.NewStyle().BorderForeground(highlightColor).Padding(2, 0).Align(lipgloss.Center).Border(lipgloss.NormalBorder()).UnsetBorderTop()
	snippetCatStyle   = lipgloss.NewStyle().BorderForeground(highlightColor).Padding(1, 0).Align(lipgloss.Center).Border(lipgloss.NormalBorder())
	snippetEditStyle  = lipgloss.NewStyle().BorderForeground(highlightColor).Align(lipgloss.Left).Padding(2).Border(lipgloss.NormalBorder())
	inputStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))
	blurredStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	focusedSubBtn     = inputStyle.Copy().Render("[ Submit ]")
	blurredSubBtn     = fmt.Sprintf("[ %s ]", blurredStyle.Render("Submit"))
	focusedBackBtn    = inputStyle.Copy().Render("[ Back ]")
	blurredBackBtn    = fmt.Sprintf("[ %s ]", blurredStyle.Render("Back"))
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
	// Screen showing a list of snippets from the selected category
	snippetScreen
	// Screen that allows the user to edit the current selected snippet
	snippetEditScreen
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
	smalScreen        bool              // true when tabs don't fit in the screen
	snippetInputs     []textinput.Model // Snippet editable fields
	snippetTokens     []interface{}
	focused           int // Current snippet input field with focus
	snippetTitle      string
}

func init() {
	// Enable debugging log if DEBUG env is not empty.
	if len(os.Getenv("DEBUG")) > 0 {
		logFile, err := tea.LogToFile("debug.log", "")
		if err != nil {
			log.Fatalln("DEBUG:", err)
		}
		defer logFile.Close()
	} else {
		log.SetOutput(ioutil.Discard)
	}
	rootCmd.AddCommand(snippetsCmd)
}

var demoSnippets = snippets{
	// categories: []string{"Database", "Logs", "Server Management", "General"},
	categories: []string{"Database", "Logs", "Server Management", "General", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
	// categories: []string{"Database", "Logs"},
	items: [][]snippet{
		{
			{"Connect to PostgreSQL", "psql -h {{host}} -p {{port}} -U {{user}} -W {{db}}"},
			{"Connect to MySQL", "mysql -u {{user}} -p {{db}}"},
			{"Show active MySQL connections", "mysql ..."},
		},
		{
			{"Monitor log", "tail -f /var/log/{{logfile}}"},
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
	fmt.Println(showSnippetsImpl(nil))
}

func showSnippetsImpl(reader io.Reader) string {
	selectedSnippet = ""
	term := console.Current()
	termSize, _ := term.Size()

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

	if reader == nil {
		reader = os.Stdin
	}

	program := tea.NewProgram(m, tea.WithInput(reader), tea.WithAltScreen())
	if err := program.Start(); err != nil {
		fmt.Println("Error running program:", err)
		return ""
	}

	return selectedSnippet
}

func ShowSnippets() string {
	return showSnippetsImpl(nil)
}

func ShowSnippetsWithReader(r io.Reader) string {
	return showSnippetsImpl(r)
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m *model) getCurrentList() *list.Model {
	if m.smalScreen {
		if m.currentScreen == snippetCategoryScreen {
			log.Println("getCurrentList: snippetCategoryScreen!")
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
			if m.currentScreen != snippetEditScreen && m.getCurrentList().FilterState() != list.Filtering {
				return m, tea.Quit
			}
		case "tab":
			m.nextInput()
			if m.currentScreen != snippetEditScreen {
				m.activeTab = min(m.activeTab+1, len(m.tabs)-1)
				return m, nil
			}
		case "right":
			if m.currentScreen == snippetEditScreen {
				if m.focused == len(m.snippetInputs) {
					m.nextInput()
				}
			} else {
				m.activeTab = min(m.activeTab+1, len(m.tabs)-1)
			}
			return m, nil
		case "shift+tab":
			m.prevInput()
			if m.currentScreen != snippetEditScreen {
				m.activeTab = max(m.activeTab-1, 0)
				return m, nil
			}
		case "up":
			m.prevInput()
		case "down":
			m.nextInput()
		case "left":
			if m.currentScreen == snippetEditScreen {
				if m.focused == (len(m.snippetInputs) + 1) {
					m.prevInput()
				}
			} else {
				m.activeTab = max(m.activeTab-1, 0)
			}
			return m, nil
		case "esc":
			if m.currentScreen == snippetEditScreen {
				m.back()
				return m, nil
			} else if m.getCurrentList().FilterState() == list.Unfiltered {
				return m, tea.Quit
			}

		case "enter":
			if m.currentScreen == snippetEditScreen {
				if m.focused == len(m.snippetInputs)+1 {
					m.back()
					return m, nil
				} else {
					return m, tea.Quit
				}
			}

			if m.getCurrentList() == &m.snippetCategories {
				m.selectedCategory = m.snippetCategories.Index()
				m.currentScreen = snippetScreen
				return m, nil
			} else if m.getCurrentList().FilterState() != list.Filtering {
				snipt, ok := m.getCurrentList().SelectedItem().(snippet)
				if ok {
					m.currentScreen = snippetEditScreen
					m.snippetTitle = snipt.title
					parseSnippet(snipt.cmd, &m)
					return m, nil
				}
			}
		}

		if m.snippetInputs != nil {
			for i := range m.snippetInputs {
				m.snippetInputs[i].Blur()
			}
			if m.focused < len(m.snippetInputs) {
				m.snippetInputs[m.focused].Focus()
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

	if m.currentScreen == snippetEditScreen {
		if m.snippetInputs != nil {
			log.Println("Updating fields...")
			cmds := make([]tea.Cmd, len(m.snippetInputs))
			for i := range m.snippetInputs {
				m.snippetInputs[i], cmds[i] = m.snippetInputs[i].Update(msg)
			}
			return m, tea.Batch(cmds...)
		}

		return m, nil
	}

	var cmd tea.Cmd

	log.Printf("Updating list %p, msg = %v\n", m.getCurrentList(), msg)
	*(m.getCurrentList()), cmd = m.getCurrentList().Update(msg)

	return m, cmd
}

func (m model) View() string {
	log.Println("View() currentScreen = ", m.currentScreen)
	if m.currentScreen == snippetEditScreen {
		return drawSnippetEditScreen(m)
	}

	var tabs string
	doc := strings.Builder{}
	var w, h int
	lst := m.getCurrentList()
	var style *lipgloss.Style

	if !m.smalScreen {
		tabs = drawTabs(m, true)
		doc.WriteString(tabs)
		doc.WriteString("\n")
		// Render snippets from the active Tab
		w = lipgloss.Width(tabs) - windowStyle.GetHorizontalFrameSize()
		h = termHeight - lipgloss.Height(tabs) - windowStyle.GetVerticalFrameSize()
		style = &windowStyle
	} else {
		w = termWidth - windowStyle.GetHorizontalFrameSize() - 2
		h = termHeight - windowStyle.GetVerticalFrameSize() + 2
		style = &snippetCatStyle
	}

	lst.SetSize(w-2, h-2)

	doc.WriteString(
		style.Width(w).
			Render(lipgloss.JoinVertical(lipgloss.Center, lst.View())))

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

func parseSnippet(snippet string, m *model) {
	m.snippetInputs = nil
	m.snippetTokens = nil
	m.focused = 0

	locs := snippetRegex.FindAllStringIndex(snippet, -1)
	log.Printf("Parse snippet: %s, tokens=%d\n", snippet, len(locs))
	if locs != nil {
		m.snippetInputs = make([]textinput.Model, len(locs))
		off := 0

		for i := range locs {
			l := locs[i]
			m.snippetTokens = append(m.snippetTokens, snippet[off:l[0]])
			arg := snippet[l[0]:l[1]]

			m.snippetInputs[i] = textinput.New()
			m.snippetInputs[i].Placeholder = strings.TrimRight(fmt.Sprintf("%s", snippetFilterRegex.ReplaceAllString(arg, "")), " ")
			if i == 0 {
				m.snippetInputs[i].Focus()
			}
			m.snippetInputs[i].CharLimit = 0
			m.snippetInputs[i].Width = 25
			m.snippetInputs[i].Prompt = fmt.Sprintf("%15s: ", m.snippetInputs[i].Placeholder)
			m.snippetInputs[i].PromptStyle = inputStyle
			m.snippetInputs[i].Validate = nil

			m.snippetTokens = append(m.snippetTokens, m.snippetInputs[i])
			off = l[1] + 1
		}

		m.focused = 0

		if off < len(snippet) {
			m.snippetTokens = append(m.snippetTokens, snippet[off:])
		}
	} else {
		selectedSnippet = snippet
	}
}

func (m *model) nextInput() {
	if m.currentScreen == snippetEditScreen {
		// components able to receive focus = input text fields + 2 buttons
		m.focused = (m.focused + 1) % (len(m.snippetInputs) + 2)
	}
}

// prevInput focuses the previous input field
func (m *model) prevInput() {
	if m.currentScreen == snippetEditScreen {
		m.focused--
		// Wrap around
		if m.focused < 0 {
			m.focused = len(m.snippetInputs) + 1
		}
	}
}

func drawSnippetEditScreen(m model) string {
	w, h := docStyle.GetFrameSize()

	form := strings.Builder{}
	result := strings.Builder{}
	snippet := strings.Builder{}

	result.WriteString(inputStyle.Render(fmt.Sprintf("%15s:", "Snippet")))
	result.WriteString(" " + m.snippetTitle)
	result.WriteString("\n\n")
	result.WriteString(inputStyle.Render(fmt.Sprintf("%15s: ", "Command")))

	if m.snippetInputs != nil {
		j := 0
		for i, s := range m.snippetTokens {
			switch v := s.(type) {
			case string:
				result.WriteString(v)
				snippet.WriteString(v)
			case textinput.Model:
				value := m.snippetInputs[j].Value()
				if value == "" {
					result.WriteString(fmt.Sprintf("<%s>", m.snippetInputs[j].Placeholder))
					snippet.WriteString(fmt.Sprintf("<%s>", m.snippetInputs[j].Placeholder))
				} else {
					result.WriteString(value)
					snippet.WriteString(value)
				}

				if i < len(m.snippetTokens) {
					snippet.WriteRune(' ')
					result.WriteRune(' ')
				}
				form.WriteString(m.snippetInputs[j].View())
				form.WriteRune('\n')
				j += 1
			}
		}
		selectedSnippet = snippet.String()
	} else {
		result.WriteString(selectedSnippet)
	}

	result.WriteString("\n\n")

	button := &blurredSubBtn
	if m.focused == len(m.snippetInputs) {
		button = &focusedSubBtn
	}

	fmt.Fprintf(&form, "\n\n%30s", *button)
	button = &blurredBackBtn
	if m.focused == len(m.snippetInputs)+1 {
		button = &focusedBackBtn
	}
	fmt.Fprintf(&form, "  %s", *button)

	return docStyle.Render(snippetEditStyle.
		Width(termWidth - w).
		Height(termHeight - h - 4).
		Render(result.String() + form.String()))
}

func (m *model) isBackPressed() bool {
	return m.currentScreen == snippetEditScreen && m.focused == len(m.snippetInputs)+1
}

func (m *model) back() {
	m.snippetInputs = nil
	m.focused = 0
	m.currentScreen = snippetScreen
}
