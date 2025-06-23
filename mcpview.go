package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os/exec"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// JSON-RPC 2.0 message types
type JSONRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

type JSONRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *JSONRPCError `json:"error,omitempty"`
}

type JSONRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// MCP protocol structures
type InitializeParams struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    map[string]interface{} `json:"capabilities"`
	ClientInfo      ClientInfo             `json:"clientInfo"`
}

type ClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema interface{} `json:"inputSchema"`
}

type ToolsListResult struct {
	Tools []Tool `json:"tools"`
}

type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

type ResourcesListResult struct {
	Resources []Resource `json:"resources"`
}

// Application state
type AppState int

const (
	StateConnection AppState = iota
	StateToolsList
	StateToolDetail
	StateResourcesList
)

// MCP Client handles connection and communication
type MCPClient struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	reader *bufio.Scanner
	nextID int
}

func NewMCPClient() *MCPClient {
	return &MCPClient{
		nextID: 1,
	}
}

func (c *MCPClient) Connect(serverCmd string) error {
	parts := strings.Fields(serverCmd)
	if len(parts) == 0 {
		return fmt.Errorf("empty server command")
	}

	c.cmd = exec.Command(parts[0], parts[1:]...)
	
	stdin, err := c.cmd.StdinPipe()
	if err != nil {
		return err
	}
	c.stdin = stdin

	stdout, err := c.cmd.StdoutPipe()
	if err != nil {
		return err
	}
	c.stdout = stdout
	c.reader = bufio.NewScanner(stdout)

	return c.cmd.Start()
}

func (c *MCPClient) sendRequest(method string, params interface{}) (*JSONRPCResponse, error) {
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      c.nextID,
		Method:  method,
		Params:  params,
	}
	c.nextID++

	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	_, err = c.stdin.Write(append(data, '\n'))
	if err != nil {
		return nil, err
	}

	if !c.reader.Scan() {
		return nil, fmt.Errorf("no response received")
	}

	var resp JSONRPCResponse
	err = json.Unmarshal(c.reader.Bytes(), &resp)
	if err != nil {
		return nil, err
	}

	return &resp, nil
}

func (c *MCPClient) Initialize() error {
	params := InitializeParams{
		ProtocolVersion: "2024-11-05",
		Capabilities:    map[string]interface{}{},
		ClientInfo: ClientInfo{
			Name:    "mcpview",
			Version: "1.0.0",
		},
	}

	resp, err := c.sendRequest("initialize", params)
	if err != nil {
		return err
	}

	if resp.Error != nil {
		return fmt.Errorf("initialize failed: %s", resp.Error.Message)
	}

	// Send initialized notification
	notification := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "notifications/initialized",
	}

	data, err := json.Marshal(notification)
	if err != nil {
		return err
	}

	_, err = c.stdin.Write(append(data, '\n'))
	return err
}

func (c *MCPClient) ListTools() ([]Tool, error) {
	resp, err := c.sendRequest("tools/list", nil)
	if err != nil {
		return nil, err
	}

	if resp.Error != nil {
		return nil, fmt.Errorf("tools/list failed: %s", resp.Error.Message)
	}

	var result ToolsListResult
	data, err := json.Marshal(resp.Result)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(data, &result)
	if err != nil {
		return nil, err
	}

	return result.Tools, nil
}

func (c *MCPClient) ListResources() ([]Resource, error) {
	resp, err := c.sendRequest("resources/list", nil)
	if err != nil {
		return nil, err
	}

	if resp.Error != nil {
		return nil, fmt.Errorf("resources/list failed: %s", resp.Error.Message)
	}

	var result ResourcesListResult
	data, err := json.Marshal(resp.Result)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(data, &result)
	if err != nil {
		return nil, err
	}

	return result.Resources, nil
}

func (c *MCPClient) CallTool(name string, arguments map[string]interface{}) (*JSONRPCResponse, error) {
	params := map[string]interface{}{
		"name":      name,
		"arguments": arguments,
	}

	return c.sendRequest("tools/call", params)
}

func (c *MCPClient) Close() error {
	if c.stdin != nil {
		c.stdin.Close()
	}
	if c.stdout != nil {
		c.stdout.Close()
	}
	if c.cmd != nil && c.cmd.Process != nil {
		return c.cmd.Process.Kill()
	}
	return nil
}

// Bubbletea Model
type Model struct {
	state       AppState
	client      *MCPClient
	serverCmd   string
	tools       []Tool
	resources   []Resource
	selectedTool int
	selectedResource int
	inputBuffer string
	cursor      int
	error       string
	loading     bool
	width       int
	height      int
}

type ConnectedMsg struct{}
type ToolsLoadedMsg struct{ tools []Tool }
type ResourcesLoadedMsg struct{ resources []Resource }
type ErrorMsg struct{ err error }

func NewModel() Model {
	return Model{
		state:     StateConnection,
		client:    NewMCPClient(),
		serverCmd: "",
		cursor:    0,
	}
}

func (m Model) Init() tea.Cmd {
	return nil
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		switch m.state {
		case StateConnection:
			return m.updateConnection(msg)
		case StateToolsList:
			return m.updateToolsList(msg)
		case StateToolDetail:
			return m.updateToolDetail(msg)
		case StateResourcesList:
			return m.updateResourcesList(msg)
		}

	case ConnectedMsg:
		m.loading = false
		m.state = StateToolsList
		return m, m.loadTools()

	case ToolsLoadedMsg:
		m.tools = msg.tools
		m.loading = false
		return m, nil

	case ResourcesLoadedMsg:
		m.resources = msg.resources
		m.loading = false
		return m, nil

	case ErrorMsg:
		m.error = msg.err.Error()
		m.loading = false
		return m, nil
	}

	return m, nil
}

func (m Model) updateConnection(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		return m, tea.Quit
	case "enter":
		if m.serverCmd != "" {
			m.loading = true
			m.error = ""
			return m, m.connect()
		}
	case "backspace":
		if len(m.serverCmd) > 0 {
			m.serverCmd = m.serverCmd[:len(m.serverCmd)-1]
		}
	default:
		m.serverCmd += msg.String()
	}
	return m, nil
}

func (m Model) updateToolsList(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		return m, tea.Quit
	case "up", "k":
		if m.selectedTool > 0 {
			m.selectedTool--
		}
	case "down", "j":
		if m.selectedTool < len(m.tools)-1 {
			m.selectedTool++
		}
	case "enter":
		if len(m.tools) > 0 {
			m.state = StateToolDetail
		}
	case "r":
		m.state = StateResourcesList
		m.loading = true
		return m, m.loadResources()
	case "c":
		m.state = StateConnection
		m.serverCmd = ""
		m.client.Close()
	}
	return m, nil
}

func (m Model) updateToolDetail(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		return m, tea.Quit
	case "esc":
		m.state = StateToolsList
	case "t":
		// Test tool with empty arguments
		return m, m.testTool()
	}
	return m, nil
}

func (m Model) updateResourcesList(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		return m, tea.Quit
	case "esc":
		m.state = StateToolsList
	case "up", "k":
		if m.selectedResource > 0 {
			m.selectedResource--
		}
	case "down", "j":
		if m.selectedResource < len(m.resources)-1 {
			m.selectedResource++
		}
	}
	return m, nil
}

func (m Model) connect() tea.Cmd {
	return func() tea.Msg {
		err := m.client.Connect(m.serverCmd)
		if err != nil {
			return ErrorMsg{err}
		}

		err = m.client.Initialize()
		if err != nil {
			return ErrorMsg{err}
		}

		return ConnectedMsg{}
	}
}

func (m Model) loadTools() tea.Cmd {
	return func() tea.Msg {
		tools, err := m.client.ListTools()
		if err != nil {
			return ErrorMsg{err}
		}
		return ToolsLoadedMsg{tools}
	}
}

func (m Model) loadResources() tea.Cmd {
	return func() tea.Msg {
		resources, err := m.client.ListResources()
		if err != nil {
			return ErrorMsg{err}
		}
		return ResourcesLoadedMsg{resources}
	}
}

func (m Model) testTool() tea.Cmd {
	return func() tea.Msg {
		if len(m.tools) == 0 {
			return ErrorMsg{fmt.Errorf("no tools available")}
		}

		tool := m.tools[m.selectedTool]
		resp, err := m.client.CallTool(tool.Name, map[string]interface{}{})
		if err != nil {
			return ErrorMsg{err}
		}

		// For now, just return as error to display the response
		var buf bytes.Buffer
		json.Indent(&buf, []byte(fmt.Sprintf("%+v", resp)), "", "  ")
		return ErrorMsg{fmt.Errorf("Tool Response:\n%s", buf.String())}
	}
}

func (m Model) View() string {
	var styles = struct {
		title   lipgloss.Style
		header  lipgloss.Style
		selected lipgloss.Style
		normal  lipgloss.Style
		error   lipgloss.Style
		loading lipgloss.Style
	}{
		title: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("205")).
			MarginBottom(1),
		header: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("99")).
			MarginBottom(1),
		selected: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("212")).
			Background(lipgloss.Color("57")),
		normal: lipgloss.NewStyle().
			Foreground(lipgloss.Color("252")),
		error: lipgloss.NewStyle().
			Foreground(lipgloss.Color("196")).
			MarginTop(1),
		loading: lipgloss.NewStyle().
			Foreground(lipgloss.Color("11")).
			MarginTop(1),
	}

	switch m.state {
	case StateConnection:
		s := styles.title.Render("MCP Explorer")
		s += "\n\n" + "Enter MCP server command (e.g., 'python server.py'):"
		s += "\n" + styles.normal.Render("> "+m.serverCmd)
		s += "\n\n" + "Press Enter to connect, Ctrl+C to quit"

		if m.loading {
			s += "\n" + styles.loading.Render("Connecting...")
		}

		if m.error != "" {
			s += "\n" + styles.error.Render("Error: "+m.error)
		}
		return s

	case StateToolsList:
		s := styles.title.Render("MCP Tools")
		s += "\n" + styles.header.Render(fmt.Sprintf("Connected to: %s", m.serverCmd))
		
		if m.loading {
			s += "\n" + styles.loading.Render("Loading tools...")
		} else if len(m.tools) == 0 {
			s += "\n" + styles.normal.Render("No tools available")
		} else {
			s += "\n\nTools:"
			for i, tool := range m.tools {
				style := styles.normal
				if i == m.selectedTool {
					style = styles.selected
				}
				s += "\n" + style.Render(fmt.Sprintf("  %s - %s", tool.Name, tool.Description))
			}
		}

		s += "\n\n" + "↑/↓ navigate, Enter view details, R resources, C reconnect, Q quit"

		if m.error != "" {
			s += "\n" + styles.error.Render("Error: "+m.error)
		}
		return s

	case StateToolDetail:
		if len(m.tools) == 0 {
			return "No tool selected"
		}

		tool := m.tools[m.selectedTool]
		s := styles.title.Render("Tool Details")
		s += "\n\n" + styles.header.Render("Name: "+tool.Name)
		s += "\n" + styles.normal.Render("Description: "+tool.Description)
		
		if tool.InputSchema != nil {
			schemaBytes, _ := json.MarshalIndent(tool.InputSchema, "", "  ")
			s += "\n\n" + styles.header.Render("Input Schema:")
			s += "\n" + styles.normal.Render(string(schemaBytes))
		}

		s += "\n\n" + "T test tool, Esc back, Q quit"

		if m.error != "" {
			s += "\n" + styles.error.Render("Error: "+m.error)
		}
		return s

	case StateResourcesList:
		s := styles.title.Render("MCP Resources")
		
		if m.loading {
			s += "\n" + styles.loading.Render("Loading resources...")
		} else if len(m.resources) == 0 {
			s += "\n" + styles.normal.Render("No resources available")
		} else {
			s += "\n\nResources:"
			for i, resource := range m.resources {
				style := styles.normal
				if i == m.selectedResource {
					style = styles.selected
				}
				s += "\n" + style.Render(fmt.Sprintf("  %s - %s", resource.Name, resource.Description))
			}
		}

		s += "\n\n" + "↑/↓ navigate, Esc back, Q quit"

		if m.error != "" {
			s += "\n" + styles.error.Render("Error: "+m.error)
		}
		return s
	}

	return "Unknown state"
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	model := NewModel()
	p := tea.NewProgram(&model, tea.WithAltScreen())

	go func() {
		<-ctx.Done()
		p.Quit()
	}()

	if _, err := p.Run(); err != nil {
		log.Fatal(err)
	}
}