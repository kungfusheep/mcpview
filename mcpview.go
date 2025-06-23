package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

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

// Message logging
type MessageDirection int

const (
	DirectionOutbound MessageDirection = iota
	DirectionInbound
)

type LoggedMessage struct {
	Timestamp time.Time         `json:"timestamp"`
	Direction MessageDirection  `json:"direction"`
	Content   json.RawMessage   `json:"content"`
	Pretty    string           `json:"-"` // Pretty-printed version
}

// Application state
type AppState int

const (
	StateConnection AppState = iota
	StateToolsList
	StateToolDetail
	StateResourcesList
	StateMessageHistory
	StateDebugMode
)

// JSON Schema structures for parsing tool input schemas
type JSONSchema struct {
	Type       string                 `json:"type"`
	Properties map[string]JSONSchema  `json:"properties"`
	Required   []string               `json:"required"`
	Items      *JSONSchema            `json:"items"`
	Enum       []interface{}          `json:"enum"`
	Default    interface{}            `json:"default"`
	Title      string                 `json:"title"`
	Description string                 `json:"description"`
}

// Form field types
type FormFieldType int

const (
	FieldTypeString FormFieldType = iota
	FieldTypeNumber
	FieldTypeBoolean
	FieldTypeArray
	FieldTypeObject
)

// Form field represents a single input field in the form
type FormField struct {
	Name        string
	Type        FormFieldType
	Label       string
	Description string
	Required    bool
	Value       string
	Options     []string // For enum fields
	Schema      JSONSchema
}

// Form state for tool detail screen
type FormState struct {
	Fields        []FormField
	CurrentField  int
	Mode          FormMode
}

type FormMode int

const (
	FormModeView FormMode = iota
	FormModeEdit
)

// MCP Client handles connection and communication
type MCPClient struct {
	cmd           *exec.Cmd
	stdin         io.WriteCloser
	stdout        io.ReadCloser
	reader        *bufio.Scanner
	nextID        int
	messageLog    []LoggedMessage
	logCallback   func(LoggedMessage) // Callback for real-time message updates
}

func NewMCPClient() *MCPClient {
	return &MCPClient{
		nextID:     1,
		messageLog: make([]LoggedMessage, 0),
	}
}

func (c *MCPClient) SetLogCallback(callback func(LoggedMessage)) {
	c.logCallback = callback
}

// GetLatestMessages returns the last N messages
func (c *MCPClient) GetLatestMessages(n int) []LoggedMessage {
	if len(c.messageLog) <= n {
		return c.messageLog
	}
	return c.messageLog[len(c.messageLog)-n:]
}

func (c *MCPClient) logMessage(direction MessageDirection, content []byte) {
	msg := LoggedMessage{
		Timestamp: time.Now(),
		Direction: direction,
		Content:   json.RawMessage(content),
	}
	
	// Pretty print the JSON
	var prettyBuf bytes.Buffer
	if err := json.Indent(&prettyBuf, content, "", "  "); err == nil {
		msg.Pretty = prettyBuf.String()
	} else {
		msg.Pretty = string(content)
	}
	
	c.messageLog = append(c.messageLog, msg)
	
	// Call callback if set
	if c.logCallback != nil {
		c.logCallback(msg)
	}
}

func (c *MCPClient) GetMessageLog() []LoggedMessage {
	return c.messageLog
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

	// Log outbound message
	c.logMessage(DirectionOutbound, data)

	_, err = c.stdin.Write(append(data, '\n'))
	if err != nil {
		return nil, err
	}

	if !c.reader.Scan() {
		return nil, fmt.Errorf("no response received")
	}

	responseData := c.reader.Bytes()
	// Log inbound message
	c.logMessage(DirectionInbound, responseData)

	var resp JSONRPCResponse
	err = json.Unmarshal(responseData, &resp)
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

// Schema parsing and form generation functions
func parseJSONSchema(schemaInterface interface{}) (*JSONSchema, error) {
	if schemaInterface == nil {
		return nil, fmt.Errorf("empty schema")
	}

	schemaBytes, err := json.Marshal(schemaInterface)
	if err != nil {
		return nil, err
	}

	var schema JSONSchema
	err = json.Unmarshal(schemaBytes, &schema)
	if err != nil {
		return nil, err
	}

	return &schema, nil
}

func generateFormFromSchema(schema *JSONSchema) []FormField {
	var fields []FormField

	if schema.Type == "object" && schema.Properties != nil {
		for propName, propSchema := range schema.Properties {
			field := FormField{
				Name:        propName,
				Label:       propName,
				Description: propSchema.Description,
				Required:    contains(schema.Required, propName),
				Schema:      propSchema,
			}

			if propSchema.Title != "" {
				field.Label = propSchema.Title
			}

			// Set field type based on schema
			switch propSchema.Type {
			case "string":
				field.Type = FieldTypeString
				if len(propSchema.Enum) > 0 {
					field.Options = enumToStrings(propSchema.Enum)
				}
			case "number", "integer":
				field.Type = FieldTypeNumber
			case "boolean":
				field.Type = FieldTypeBoolean
			case "array":
				field.Type = FieldTypeArray
			case "object":
				field.Type = FieldTypeObject
			default:
				field.Type = FieldTypeString
			}

			// Set default value
			if propSchema.Default != nil {
				field.Value = fmt.Sprintf("%v", propSchema.Default)
			}

			fields = append(fields, field)
		}
	}

	return fields
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func enumToStrings(enum []interface{}) []string {
	var result []string
	for _, v := range enum {
		result = append(result, fmt.Sprintf("%v", v))
	}
	return result
}

func buildArgumentsFromForm(fields []FormField) map[string]interface{} {
	args := make(map[string]interface{})

	for _, field := range fields {
		if field.Value == "" && !field.Required {
			continue
		}

		switch field.Type {
		case FieldTypeString:
			args[field.Name] = field.Value
		case FieldTypeNumber:
			if field.Value != "" {
				if strings.Contains(field.Value, ".") {
					if f, err := parseFloat(field.Value); err == nil {
						args[field.Name] = f
					}
				} else {
					if i, err := parseInt(field.Value); err == nil {
						args[field.Name] = i
					}
				}
			}
		case FieldTypeBoolean:
			args[field.Name] = field.Value == "true" || field.Value == "yes" || field.Value == "1"
		case FieldTypeArray:
			if field.Value != "" {
				// Simple comma-separated array for now
				args[field.Name] = strings.Split(strings.TrimSpace(field.Value), ",")
			}
		case FieldTypeObject:
			if field.Value != "" {
				var obj interface{}
				if err := json.Unmarshal([]byte(field.Value), &obj); err == nil {
					args[field.Name] = obj
				}
			}
		}
	}

	return args
}

func parseFloat(s string) (float64, error) {
	return strconv.ParseFloat(s, 64)
}

func parseInt(s string) (int, error) {
	return strconv.Atoi(s)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Debug mode layout
type DebugLayout struct {
	messagePaneHeight int
	messageScroll     int
	mainPaneHeight    int
	splitRatio        float64 // 0.0 to 1.0, portion for message pane
}

// Bubbletea Model
type Model struct {
	state            AppState
	client           *MCPClient
	serverCmd        string
	tools            []Tool
	resources        []Resource
	selectedTool     int
	selectedResource int
	selectedMessage  int
	inputBuffer      string
	cursor           int
	error            string
	loading          bool
	width            int
	height           int
	formState        FormState
	messageHistory   []LoggedMessage
	debugLayout      DebugLayout
	liveMessages     []LoggedMessage // For real-time updates
}

type ConnectedMsg struct{}
type ToolsLoadedMsg struct{ tools []Tool }
type ResourcesLoadedMsg struct{ resources []Resource }
type ErrorMsg struct{ err error }
type MessageLoggedMsg struct{ message LoggedMessage }

func NewModel() Model {
	client := NewMCPClient()
	m := Model{
		state:          StateConnection,
		client:         client,
		serverCmd:      "",
		cursor:         0,
		messageHistory: make([]LoggedMessage, 0),
		liveMessages:   make([]LoggedMessage, 0),
		debugLayout: DebugLayout{
			splitRatio: 0.4, // 40% for message pane
		},
	}
	
	// Set up message logging callback for real-time updates
	client.SetLogCallback(func(msg LoggedMessage) {
		// This will trigger a MessageLoggedMsg
	})
	
	return m
}

func (m Model) Init() tea.Cmd {
	// Auto-connect if serverCmd is set
	if m.serverCmd != "" && m.loading {
		return m.connect()
	}
	return nil
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		// Recalculate debug layout if in debug mode
		if m.state == StateDebugMode {
			m.debugLayout.messagePaneHeight = int(float64(m.height) * m.debugLayout.splitRatio)
			m.debugLayout.mainPaneHeight = m.height - m.debugLayout.messagePaneHeight
		}
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
		case StateMessageHistory:
			return m.updateMessageHistory(msg)
		case StateDebugMode:
			return m.updateDebugMode(msg)
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

	case MessageLoggedMsg:
		m.messageHistory = m.client.GetMessageLog()
		m.liveMessages = m.client.GetMessageLog() // Update live messages too
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
			// Generate form from tool schema
			tool := m.tools[m.selectedTool]
			if schema, err := parseJSONSchema(tool.InputSchema); err == nil {
				m.formState = FormState{
					Fields:       generateFormFromSchema(schema),
					CurrentField: 0,
					Mode:         FormModeView,
				}
			} else {
				m.formState = FormState{
					Fields: []FormField{},
					Mode:   FormModeView,
				}
			}
		}
	case "r":
		m.state = StateResourcesList
		m.loading = true
		return m, m.loadResources()
	case "m":
		m.state = StateMessageHistory
		m.messageHistory = m.client.GetMessageLog()
		m.selectedMessage = 0
	case "d":
		m.state = StateDebugMode
		m.liveMessages = m.client.GetMessageLog()
		m.debugLayout.messagePaneHeight = int(float64(m.height) * m.debugLayout.splitRatio)
		m.debugLayout.mainPaneHeight = m.height - m.debugLayout.messagePaneHeight
	case "c":
		m.state = StateConnection
		m.serverCmd = ""
		m.client.Close()
	}
	return m, nil
}

func (m Model) updateToolDetail(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.formState.Mode {
	case FormModeView:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "esc":
			m.state = StateToolsList
		case "up", "k":
			if m.formState.CurrentField > 0 {
				m.formState.CurrentField--
			}
		case "down", "j":
			if m.formState.CurrentField < len(m.formState.Fields)-1 {
				m.formState.CurrentField++
			}
		case "enter", "e":
			if len(m.formState.Fields) > 0 {
				m.formState.Mode = FormModeEdit
			}
		case "t":
			// Test tool with form arguments
			return m, m.testToolWithForm()
		}
	case FormModeEdit:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "esc":
			m.formState.Mode = FormModeView
		case "enter":
			m.formState.Mode = FormModeView
		case "backspace":
			if len(m.formState.Fields) > m.formState.CurrentField {
				field := &m.formState.Fields[m.formState.CurrentField]
				if len(field.Value) > 0 {
					field.Value = field.Value[:len(field.Value)-1]
				}
			}
		default:
			// Add character to current field
			if len(m.formState.Fields) > m.formState.CurrentField {
				field := &m.formState.Fields[m.formState.CurrentField]
				if len(msg.String()) == 1 {
					field.Value += msg.String()
				}
			}
		}
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

func (m Model) updateMessageHistory(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		return m, tea.Quit
	case "esc":
		m.state = StateToolsList
	case "up", "k":
		if m.selectedMessage > 0 {
			m.selectedMessage--
		}
	case "down", "j":
		if m.selectedMessage < len(m.messageHistory)-1 {
			m.selectedMessage++
		}
	}
	return m, nil
}

func (m Model) updateDebugMode(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		return m, tea.Quit
	case "esc":
		m.state = StateToolsList
	case "up", "k":
		// Scroll up in message pane
		if m.debugLayout.messageScroll > 0 {
			m.debugLayout.messageScroll--
		}
	case "down", "j":
		// Scroll down in message pane
		maxScroll := len(m.liveMessages) - m.debugLayout.messagePaneHeight + 5
		if maxScroll < 0 {
			maxScroll = 0
		}
		if m.debugLayout.messageScroll < maxScroll {
			m.debugLayout.messageScroll++
		}
	case "r":
		// Refresh - go to resources
		m.loading = true
		return m, m.loadResources()
	case "t":
		// Go to tools list in the main pane while keeping debug mode
		// This allows tool testing while watching messages
		m.loading = true
		return m, m.loadTools()
	case "enter":
		// Test selected tool (if any) while in debug mode
		if len(m.tools) > 0 && m.selectedTool < len(m.tools) {
			return m, m.testTool()
		}
	case "+":
		// Increase message pane size
		if m.debugLayout.splitRatio < 0.8 {
			m.debugLayout.splitRatio += 0.1
			m.debugLayout.messagePaneHeight = int(float64(m.height) * m.debugLayout.splitRatio)
			m.debugLayout.mainPaneHeight = m.height - m.debugLayout.messagePaneHeight
		}
	case "-":
		// Decrease message pane size
		if m.debugLayout.splitRatio > 0.2 {
			m.debugLayout.splitRatio -= 0.1
			m.debugLayout.messagePaneHeight = int(float64(m.height) * m.debugLayout.splitRatio)
			m.debugLayout.mainPaneHeight = m.height - m.debugLayout.messagePaneHeight
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

func (m Model) testToolWithForm() tea.Cmd {
	return func() tea.Msg {
		if len(m.tools) == 0 {
			return ErrorMsg{fmt.Errorf("no tools available")}
		}

		tool := m.tools[m.selectedTool]
		args := buildArgumentsFromForm(m.formState.Fields)
		
		resp, err := m.client.CallTool(tool.Name, args)
		if err != nil {
			return ErrorMsg{err}
		}

		// Display the response
		var buf bytes.Buffer
		if resp.Result != nil {
			resultBytes, _ := json.MarshalIndent(resp.Result, "", "  ")
			buf.WriteString("Tool Response:\n")
			buf.Write(resultBytes)
		} else if resp.Error != nil {
			buf.WriteString(fmt.Sprintf("Tool Error: %s\n", resp.Error.Message))
			if resp.Error.Data != nil {
				dataBytes, _ := json.MarshalIndent(resp.Error.Data, "", "  ")
				buf.Write(dataBytes)
			}
		}
		
		return ErrorMsg{fmt.Errorf(buf.String())}
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

		s += "\n\n" + "↑/↓ navigate, Enter view details, R resources, M messages, D debug, C reconnect, Q quit"

		if m.error != "" {
			s += "\n" + styles.error.Render("Error: "+m.error)
		}
		return s

	case StateToolDetail:
		if len(m.tools) == 0 {
			return "No tool selected"
		}

		tool := m.tools[m.selectedTool]
		s := styles.title.Render("Tool: " + tool.Name)
		s += "\n" + styles.normal.Render(tool.Description)
		
		if len(m.formState.Fields) == 0 {
			s += "\n\n" + styles.normal.Render("No parameters required")
		} else {
			s += "\n\n" + styles.header.Render("Parameters:")
			
			for i, field := range m.formState.Fields {
				fieldStyle := styles.normal
				if i == m.formState.CurrentField {
					if m.formState.Mode == FormModeEdit {
						fieldStyle = styles.selected.Copy().Foreground(lipgloss.Color("11"))
					} else {
						fieldStyle = styles.selected
					}
				}
				
				// Field label with required indicator
				label := field.Label
				if field.Required {
					label += " *"
				}
				
				// Field value display
				value := field.Value
				if value == "" {
					value = "(empty)"
				}
				
				// Field type indicator
				typeStr := ""
				switch field.Type {
				case FieldTypeString:
					typeStr = "string"
				case FieldTypeNumber:
					typeStr = "number"
				case FieldTypeBoolean:
					typeStr = "boolean"
				case FieldTypeArray:
					typeStr = "array"
				case FieldTypeObject:
					typeStr = "object"
				}
				
				fieldLine := fmt.Sprintf("  %s (%s): %s", label, typeStr, value)
				s += "\n" + fieldStyle.Render(fieldLine)
				
				// Show description if available
				if field.Description != "" {
					s += "\n" + styles.normal.Copy().Faint(true).Render("    " + field.Description)
				}
				
				// Show options for enum fields
				if len(field.Options) > 0 {
					s += "\n" + styles.normal.Copy().Faint(true).Render("    Options: " + strings.Join(field.Options, ", "))
				}
			}
		}

		// Instructions based on mode
		if m.formState.Mode == FormModeEdit {
			s += "\n\n" + "Editing field. Type to enter value, Enter to save, Esc to cancel"
		} else {
			s += "\n\n" + "↑/↓ navigate, Enter/E edit field, T test tool, Esc back, Q quit"
		}

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

	case StateMessageHistory:
		s := styles.title.Render("Message History")
		s += "\n" + styles.header.Render(fmt.Sprintf("Connected to: %s", m.serverCmd))
		
		if len(m.messageHistory) == 0 {
			s += "\n" + styles.normal.Render("No messages yet")
		} else {
			s += "\n\nMessages:"
			for i, msg := range m.messageHistory {
				style := styles.normal
				if i == m.selectedMessage {
					style = styles.selected
				}
				
				// Direction indicator
				direction := "→" // outbound
				if msg.Direction == DirectionInbound {
					direction = "←" // inbound
				}
				
				timestamp := msg.Timestamp.Format("15:04:05.000")
				s += "\n" + style.Render(fmt.Sprintf("  %s %s %s", direction, timestamp, string(msg.Content)[:min(100, len(msg.Content))]))
				
				// Show pretty-printed version if this is the selected message
				if i == m.selectedMessage && msg.Pretty != "" {
					s += "\n\n" + styles.header.Render("Pretty JSON:")
					s += "\n" + styles.normal.Render(msg.Pretty)
				}
			}
		}
		
		s += "\n\n" + "↑/↓ navigate messages, Esc back, Q quit"
		
		if m.error != "" {
			s += "\n" + styles.error.Render("Error: "+m.error)
		}
		return s

	case StateDebugMode:
		// Split pane debug mode - message pane at top, main content below
		messagePaneHeight := m.debugLayout.messagePaneHeight
		mainPaneHeight := m.debugLayout.mainPaneHeight
		
		// Message pane header
		s := styles.title.Render("Debug Mode - Live Messages")
		s += "\n" + styles.header.Render(fmt.Sprintf("Connected to: %s | Messages: %d", m.serverCmd, len(m.liveMessages)))
		
		// Draw message pane border
		s += "\n" + strings.Repeat("─", m.width)
		
		// Show live messages in the top pane
		startIdx := m.debugLayout.messageScroll
		endIdx := min(startIdx+messagePaneHeight-4, len(m.liveMessages))
		
		if len(m.liveMessages) == 0 {
			s += "\n" + styles.normal.Render("No messages yet...")
		} else {
			for i := startIdx; i < endIdx; i++ {
				msg := m.liveMessages[i]
				
				// Direction and timestamp
				direction := "→"
				color := "blue"
				if msg.Direction == DirectionInbound {
					direction = "←"
					color = "green"
				}
				
				timestamp := msg.Timestamp.Format("15:04:05.000")
				msgStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(color))
				
				// Show compact message info
				var compact string
				var jsonObj map[string]interface{}
				if err := json.Unmarshal(msg.Content, &jsonObj); err == nil {
					if method, ok := jsonObj["method"].(string); ok {
						compact = fmt.Sprintf("Method: %s", method)
					} else if result := jsonObj["result"]; result != nil {
						compact = "Response: success"
					} else if errObj := jsonObj["error"]; errObj != nil {
						compact = "Response: error"
					} else {
						compact = "JSON message"
					}
				} else {
					compact = "Raw message"
				}
				
				s += "\n" + msgStyle.Render(fmt.Sprintf("%s %s %s", direction, timestamp, compact))
			}
			
			// Show scroll indicator if there are more messages
			if endIdx < len(m.liveMessages) {
				s += "\n" + styles.normal.Copy().Faint(true).Render(fmt.Sprintf("... %d more messages (scroll down)", len(m.liveMessages)-endIdx))
			}
		}
		
		// Separator between panes
		s += "\n" + strings.Repeat("─", m.width)
		
		// Main pane - show tools list
		s += "\n" + styles.header.Render("Tools:")
		if len(m.tools) == 0 {
			s += "\n" + styles.normal.Render("No tools available")
		} else {
			// Show limited tools list to fit in remaining space
			maxTools := mainPaneHeight - 6
			for i, tool := range m.tools {
				if i >= maxTools {
					break
				}
				style := styles.normal
				if i == m.selectedTool {
					style = styles.selected
				}
				s += "\n" + style.Render(fmt.Sprintf("  %s - %s", tool.Name, tool.Description))
			}
		}
		
		// Debug mode instructions
		s += "\n\n" + styles.normal.Copy().Faint(true).Render("↑/↓ scroll messages, +/- resize panes, Enter test tool, T tools, R resources, Esc back, Q quit")
		
		if m.error != "" {
			s += "\n" + styles.error.Render("Error: "+m.error)
		}
		return s
	}

	return "Unknown state"
}

func main() {
	// Parse command line flags
	debugMode := flag.Bool("debug", false, "Start in debug mode")
	serverCmd := flag.String("server", "", "MCP server command to connect to automatically")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "MCP Explorer - A comprehensive terminal UI for debugging and developing with MCP servers\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s                           # Start in normal mode\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --debug                   # Start in debug mode\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --server \"python srv.py\"  # Auto-connect to server\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --debug --server \"node server.js\" # Debug mode with auto-connect\n", os.Args[0])
	}
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	model := NewModel()
	
	// Set initial state based on flags
	if *debugMode {
		model.state = StateDebugMode
		model.debugLayout.messagePaneHeight = int(float64(25) * model.debugLayout.splitRatio) // Default height
		model.debugLayout.mainPaneHeight = 25 - model.debugLayout.messagePaneHeight
	}
	
	// Auto-connect if server specified
	if *serverCmd != "" {
		model.serverCmd = *serverCmd
		model.loading = true
	}
	
	p := tea.NewProgram(&model, tea.WithAltScreen())

	go func() {
		<-ctx.Done()
		p.Quit()
	}()

	if _, err := p.Run(); err != nil {
		log.Fatal(err)
	}
}