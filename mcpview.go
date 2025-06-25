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
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
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
	StateSessionList
	StateSessionViewer
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

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// wrapText wraps text to fit within the specified width
func wrapText(text string, width int) []string {
	if width <= 0 {
		return []string{text}
	}
	
	var lines []string
	words := strings.Fields(text)
	if len(words) == 0 {
		return []string{""}
	}
	
	currentLine := words[0]
	for _, word := range words[1:] {
		if len(currentLine)+1+len(word) <= width {
			currentLine += " " + word
		} else {
			lines = append(lines, currentLine)
			currentLine = word
		}
	}
	if currentLine != "" {
		lines = append(lines, currentLine)
	}
	
	return lines
}

// Calculate tool layout based on total height
func (m *Model) calculateToolLayout(tool Tool) {
	// Calculate dynamic info height based on tool description
	descLines := wrapText(tool.Description, m.width-4) // Leave margin for borders
	m.toolLayout.infoHeight = len(descLines) + 4 // Title + description + separators
	
	// Ensure minimum info height
	if m.toolLayout.infoHeight < 4 {
		m.toolLayout.infoHeight = 4
	}
	// Cap maximum info height to not overwhelm the screen
	if m.toolLayout.infoHeight > m.toolLayout.totalHeight/3 {
		m.toolLayout.infoHeight = m.toolLayout.totalHeight / 3
	}
	
	availableHeight := m.toolLayout.totalHeight - m.toolLayout.infoHeight - 4 // Reserve space for instructions
	if availableHeight < 6 {
		availableHeight = 6
	}
	
	m.toolLayout.paramHeight = int(float64(availableHeight) * m.toolLayout.paramRatio)
	m.toolLayout.responseHeight = availableHeight - m.toolLayout.paramHeight
	
	// Ensure minimum heights
	if m.toolLayout.paramHeight < 3 {
		m.toolLayout.paramHeight = 3
		m.toolLayout.responseHeight = availableHeight - 3
	}
	if m.toolLayout.responseHeight < 3 {
		m.toolLayout.responseHeight = 3
		m.toolLayout.paramHeight = availableHeight - 3
	}
}

// NewStdioProxy creates a new stdio proxy
func NewStdioProxy(targetCmd string) *StdioProxy {
	return &StdioProxy{
		targetCmd:  targetCmd,
		messageLog: make([]LoggedMessage, 0),
	}
}

// NewStdioProxyWithSession creates a new stdio proxy with session support
func NewStdioProxyWithSession(targetCmd, sessionName string) *StdioProxy {
	return &StdioProxy{
		targetCmd:   targetCmd,
		messageLog:  make([]LoggedMessage, 0),
		sessionName: sessionName,
		sessionsDir: "/tmp/mcpview-sessions", // Default
	}
}

// NewStdioProxyWithSessionAndDir creates a new stdio proxy with session support and custom directory
func NewStdioProxyWithSessionAndDir(targetCmd, sessionName, sessionsDir string) *StdioProxy {
	var socketPath string
	if sessionName != "" {
		socketPath = fmt.Sprintf("%s/%s/socket", sessionsDir, sessionName)
	}
	
	return &StdioProxy{
		targetCmd:     targetCmd,
		messageLog:    make([]LoggedMessage, 0),
		sessionName:   sessionName,
		sessionsDir:   sessionsDir,
		socketPath:    socketPath,
		socketClients: make([]net.Conn, 0),
	}
}

func (sp *StdioProxy) SetLogCallback(callback func(LoggedMessage)) {
	sp.logCallback = callback
}

func (sp *StdioProxy) logMessage(direction MessageDirection, content []byte) {
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
	
	sp.mutex.Lock()
	sp.messageLog = append(sp.messageLog, msg)
	sp.mutex.Unlock()
	
	// Broadcast to socket clients for real-time streaming
	sp.broadcastToSocketClients(msg)
	
	// Call callback if set
	if sp.logCallback != nil {
		sp.logCallback(msg)
	}
}

// Start begins the stdio proxy operation
func (sp *StdioProxy) Start() error {
	// Start the target MCP server process
	parts := strings.Fields(sp.targetCmd)
	if len(parts) == 0 {
		return fmt.Errorf("invalid target command: %s", sp.targetCmd)
	}
	
	sp.targetProc = exec.Command(parts[0], parts[1:]...)
	
	stdin, err := sp.targetProc.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdin pipe: %v", err)
	}
	sp.targetStdin = stdin
	
	stdout, err := sp.targetProc.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %v", err)
	}
	sp.targetStdout = stdout
	sp.targetReader = bufio.NewScanner(stdout)
	
	if err := sp.targetProc.Start(); err != nil {
		return fmt.Errorf("failed to start target process: %v", err)
	}
	
	sp.running = true
	
	// Create session metadata if session name is provided (this creates the directory)
	if sp.sessionName != "" {
		registry := NewSessionRegistryWithPath(sp.sessionsDir)
		if err := registry.createSession(sp.sessionName, sp.targetCmd, sp.targetProc.Process.Pid); err != nil {
			// Log error but don't fail the proxy - session is optional
			fmt.Fprintf(os.Stderr, "Warning: Failed to create session metadata: %v\n", err)
		}
	}
	
	// Start socket server for message streaming (after session directory exists)
	if err := sp.startSocketServer(); err != nil {
		// Log error but don't fail the proxy - socket is optional
		fmt.Fprintf(os.Stderr, "Warning: Failed to start socket server: %v\n", err)
	}
	
	// Start background goroutine to read from target server
	go sp.readFromTarget()
	
	return nil
}

// RunProxy runs the stdio proxy, reading from stdin and writing to stdout
func (sp *StdioProxy) RunProxy() error {
	if err := sp.Start(); err != nil {
		return err
	}
	
	// Read from our stdin (client messages) and forward to target
	stdinScanner := bufio.NewScanner(os.Stdin)
	for stdinScanner.Scan() {
		line := stdinScanner.Bytes()
		
		// Log client to server message
		sp.logMessage(DirectionOutbound, line)
		
		// Forward to target server
		if _, err := sp.targetStdin.Write(append(line, '\n')); err != nil {
			return fmt.Errorf("error writing to target server: %v", err)
		}
	}
	
	return sp.Stop()
}

// readFromTarget reads responses from target server and forwards to our stdout
func (sp *StdioProxy) readFromTarget() {
	for sp.targetReader.Scan() {
		line := sp.targetReader.Bytes()
		
		// Log server to client message
		sp.logMessage(DirectionInbound, line)
		
		// Forward to our stdout (client)
		if _, err := os.Stdout.Write(append(line, '\n')); err != nil {
			log.Printf("Error writing to stdout: %v", err)
			break
		}
	}
}

func (sp *StdioProxy) Stop() error {
	sp.running = false
	
	// Close socket connections and listener
	if sp.socketListener != nil {
		sp.socketListener.Close()
	}
	
	sp.mutex.Lock()
	for _, client := range sp.socketClients {
		client.Close()
	}
	sp.socketClients = sp.socketClients[:0]
	sp.mutex.Unlock()
	
	// Remove socket file
	if sp.socketPath != "" {
		os.Remove(sp.socketPath)
	}
	
	if sp.targetStdin != nil {
		sp.targetStdin.Close()
	}
	if sp.targetStdout != nil {
		sp.targetStdout.Close()
	}
	
	// Clean up session if this was a named session
	if sp.sessionName != "" {
		registry := NewSessionRegistryWithPath(sp.sessionsDir)
		if err := registry.removeSession(sp.sessionName); err != nil {
			// Log error but don't fail the stop operation
			fmt.Fprintf(os.Stderr, "Warning: Failed to cleanup session %s: %v\n", sp.sessionName, err)
		}
	}
	
	if sp.targetProc != nil {
		return sp.targetProc.Wait()
	}
	return nil
}

func (sp *StdioProxy) GetMessageLog() []LoggedMessage {
	sp.mutex.RLock()
	defer sp.mutex.RUnlock()
	return sp.messageLog
}

// startSocketServer creates and starts the Unix socket server for message streaming
func (sp *StdioProxy) startSocketServer() error {
	if sp.socketPath == "" {
		// No socket needed for sessions without names
		return nil
	}

	// Remove existing socket file if it exists
	os.Remove(sp.socketPath)

	listener, err := net.Listen("unix", sp.socketPath)
	if err != nil {
		return fmt.Errorf("failed to create Unix socket: %v", err)
	}

	sp.socketListener = listener

	// Start accepting connections in a goroutine
	go sp.acceptSocketConnections()

	return nil
}

// acceptSocketConnections handles incoming socket connections
func (sp *StdioProxy) acceptSocketConnections() {
	for sp.running {
		conn, err := sp.socketListener.Accept()
		if err != nil {
			if sp.running {
				fmt.Fprintf(os.Stderr, "Error accepting socket connection: %v\n", err)
			}
			break
		}

		sp.mutex.Lock()
		sp.socketClients = append(sp.socketClients, conn)
		sp.mutex.Unlock()

		// Handle client connection in separate goroutine
		go sp.handleSocketClient(conn)
	}
}

// handleSocketClient manages a single socket client connection
func (sp *StdioProxy) handleSocketClient(conn net.Conn) {
	defer func() {
		conn.Close()
		// Remove from clients list
		sp.mutex.Lock()
		for i, client := range sp.socketClients {
			if client == conn {
				sp.socketClients = append(sp.socketClients[:i], sp.socketClients[i+1:]...)
				break
			}
		}
		sp.mutex.Unlock()
	}()

	// Send existing message history to new client
	sp.mutex.RLock()
	history := make([]LoggedMessage, len(sp.messageLog))
	copy(history, sp.messageLog)
	sp.mutex.RUnlock()

	for _, msg := range history {
		sp.sendMessageToClient(conn, msg)
	}

	// Keep connection alive (client will close when done)
	buf := make([]byte, 1)
	for {
		_, err := conn.Read(buf)
		if err != nil {
			break
		}
	}
}

// sendMessageToClient sends a logged message to a socket client
func (sp *StdioProxy) sendMessageToClient(conn net.Conn, msg LoggedMessage) {
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}
	
	// Send with newline delimiter
	conn.Write(append(data, '\n'))
}

// broadcastToSocketClients sends a message to all connected socket clients
func (sp *StdioProxy) broadcastToSocketClients(msg LoggedMessage) {
	sp.mutex.RLock()
	clients := make([]net.Conn, len(sp.socketClients))
	copy(clients, sp.socketClients)
	sp.mutex.RUnlock()

	for _, client := range clients {
		sp.sendMessageToClient(client, msg)
	}
}

// Session registry functions
func NewSessionRegistry() *SessionRegistry {
	return &SessionRegistry{
		basePath: "/tmp/mcpview-sessions",
	}
}

func NewSessionRegistryWithPath(basePath string) *SessionRegistry {
	return &SessionRegistry{
		basePath: basePath,
	}
}

func (sr *SessionRegistry) createSessionDir(name string) error {
	sessionDir := sr.getSessionDir(name)
	return os.MkdirAll(sessionDir, 0755)
}

func (sr *SessionRegistry) getSessionDir(name string) string {
	return fmt.Sprintf("%s/%s", sr.basePath, name)
}

func (sr *SessionRegistry) getMetadataPath(name string) string {
	return fmt.Sprintf("%s/metadata.json", sr.getSessionDir(name))
}

func (sr *SessionRegistry) createSession(name, targetCmd string, pid int) error {
	if name == "" {
		return fmt.Errorf("session name cannot be empty")
	}
	
	if err := sr.createSessionDir(name); err != nil {
		return fmt.Errorf("failed to create session directory: %v", err)
	}

	session := ProxySession{
		Name:         name,
		TargetCmd:    targetCmd,
		PID:          pid,
		StartTime:    time.Now(),
		SocketPath:   fmt.Sprintf("%s/socket", sr.getSessionDir(name)),
		MessageCount: 0,
		LastActivity: time.Now(),
	}

	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal session metadata: %v", err)
	}

	metadataPath := sr.getMetadataPath(name)
	if err := os.WriteFile(metadataPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write session metadata: %v", err)
	}

	return nil
}

func (sr *SessionRegistry) listSessions() ([]ProxySession, error) {
	if _, err := os.Stat(sr.basePath); os.IsNotExist(err) {
		return []ProxySession{}, nil // No sessions directory yet
	}

	entries, err := os.ReadDir(sr.basePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read sessions directory: %v", err)
	}

	var sessions []ProxySession
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		sessionName := entry.Name()
		session, err := sr.loadSession(sessionName)
		if err != nil {
			// Skip invalid sessions but don't fail the whole operation
			continue
		}

		sessions = append(sessions, *session)
	}

	return sessions, nil
}

func (sr *SessionRegistry) loadSession(name string) (*ProxySession, error) {
	metadataPath := sr.getMetadataPath(name)
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read session metadata: %v", err)
	}

	var session ProxySession
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session metadata: %v", err)
	}

	return &session, nil
}

func (sr *SessionRegistry) isProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	
	// Check if process exists by sending signal 0
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	
	// On Unix systems, signal 0 can be used to check if a process exists
	// We need to import syscall for this to work properly
	err = process.Signal(syscall.Signal(0))
	return err == nil
}

func (sr *SessionRegistry) cleanupDeadSessions() error {
	sessions, err := sr.listSessions()
	if err != nil {
		return fmt.Errorf("failed to list sessions for cleanup: %v", err)
	}

	var cleanupErrors []string
	for _, session := range sessions {
		if !sr.isProcessAlive(session.PID) {
			sessionDir := sr.getSessionDir(session.Name)
			if err := os.RemoveAll(sessionDir); err != nil {
				cleanupErrors = append(cleanupErrors, fmt.Sprintf("failed to remove session %s: %v", session.Name, err))
			}
		}
	}

	if len(cleanupErrors) > 0 {
		return fmt.Errorf("cleanup errors: %s", strings.Join(cleanupErrors, "; "))
	}

	return nil
}

func (sr *SessionRegistry) removeSession(name string) error {
	sessionDir := sr.getSessionDir(name)
	return os.RemoveAll(sessionDir)
}

// Debug mode layout
type DebugLayout struct {
	messagePaneHeight int
	messageScroll     int
	mainPaneHeight    int
	splitRatio        float64 // 0.0 to 1.0, portion for message pane
}

// Tool detail layout with three panes
type ToolLayout struct {
	infoHeight     int     // Top pane: tool info (dynamic based on content)
	paramHeight    int     // Middle pane: parameters
	responseHeight int     // Bottom pane: responses
	paramScroll    int     // Scroll position for parameters
	responseScroll int     // Scroll position for responses
	paramRatio     float64 // 0.2 to 0.8, portion for parameters vs responses
	totalHeight    int     // Total available height
}

// Stdio Proxy manages MCP stdio proxy functionality
type StdioProxy struct {
	targetCmd      string
	targetProc     *exec.Cmd
	targetStdin    io.WriteCloser
	targetStdout   io.ReadCloser
	targetReader   *bufio.Scanner
	messageLog     []LoggedMessage
	logCallback    func(LoggedMessage)
	mutex          sync.RWMutex
	running        bool
	sessionName    string // Session name for proxy sessions
	sessionsDir    string // Directory for session metadata
	socketListener net.Listener // Unix socket listener for message streaming
	socketPath     string // Path to the Unix socket
	socketClients  []net.Conn // Connected socket clients
}

// Session management structures
type ProxySession struct {
	Name         string    `json:"name"`
	TargetCmd    string    `json:"targetCmd"`
	PID          int       `json:"pid"`
	StartTime    time.Time `json:"startTime"`
	SocketPath   string    `json:"socketPath"`
	MessageCount int       `json:"messageCount"`
	LastActivity time.Time `json:"lastActivity"`
}

type SessionRegistry struct {
	basePath string // /tmp/mcpview-sessions/
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
	toolLayout       ToolLayout
	liveMessages     []LoggedMessage // For real-time updates
	toolState         ToolExecutionState
	toolResponses     []ToolResponse
	currentResponse   *ToolResponse
	selectedResponse  int // For navigating through response history
	sessions          []ProxySession // Available proxy sessions
	selectedSession   int            // Currently selected session in session list
	sessionsDir       string         // Directory for session metadata
	attachedSession   *ProxySession  // Currently attached session for viewing
	sessionSocket     net.Conn       // Connection to attached session's Unix socket
	sessionMessages   []LoggedMessage // Live messages from attached session
	sessionScroll     int            // Scroll position for session messages
}

// Tool execution state
type ToolExecutionState int

const (
	ToolStateIdle ToolExecutionState = iota
	ToolStateLoading
	ToolStateSuccess
	ToolStateError
)

// Tool response structure
type ToolResponse struct {
	ToolName     string                 `json:"toolName"`
	Timestamp    time.Time             `json:"timestamp"`
	Arguments    map[string]interface{} `json:"arguments"`
	Success      bool                  `json:"success"`
	Result       interface{}           `json:"result,omitempty"`
	Error        string                `json:"error,omitempty"`
	ExecutionTime time.Duration         `json:"executionTime"`
	PrettyResult string                `json:"-"` // Pretty-printed version
}

// Message types
type ConnectedMsg struct{}
type ToolsLoadedMsg struct{ tools []Tool }
type ResourcesLoadedMsg struct{ resources []Resource }
type ErrorMsg struct{ err error }
type MessageLoggedMsg struct{ message LoggedMessage }
type ToolResponseMsg struct{ response ToolResponse }
type ToolExecutionStartMsg struct{}
type SessionAttachedMsg struct{ Session ProxySession; Socket net.Conn }
type SessionMessageMsg struct{ message LoggedMessage }

func NewModel() Model {
	client := NewMCPClient()
	m := Model{
		state:          StateConnection,
		client:         client,
		serverCmd:      "",
		cursor:         0,
		messageHistory: make([]LoggedMessage, 0),
		liveMessages:   make([]LoggedMessage, 0),
		toolState:      ToolStateIdle,
		toolResponses:  make([]ToolResponse, 0),
		debugLayout: DebugLayout{
			splitRatio: 0.4, // 40% for message pane
		},
		toolLayout: ToolLayout{
			paramRatio:  0.4, // 40% for parameters, 60% for responses
			totalHeight: 25,  // Default height
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
		// Recalculate tool layout if in tool detail mode
		if m.state == StateToolDetail && len(m.tools) > 0 {
			m.toolLayout.totalHeight = m.height
			m.calculateToolLayout(m.tools[m.selectedTool])
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
		case StateSessionList:
			return m.updateSessionList(msg)
		case StateSessionViewer:
			return m.updateSessionViewer(msg)
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

	case ToolExecutionStartMsg:
		m.toolState = ToolStateLoading
		m.error = "" // Clear any previous errors
		return m, nil

	case ToolResponseMsg:
		if msg.response.Success {
			m.toolState = ToolStateSuccess
		} else {
			m.toolState = ToolStateError
		}
		m.currentResponse = &msg.response
		// Add to response history (keep last 10)
		m.toolResponses = append(m.toolResponses, msg.response)
		if len(m.toolResponses) > 10 {
			m.toolResponses = m.toolResponses[1:]
			m.selectedResponse = max(0, m.selectedResponse-1) // Adjust selection
		} else {
			m.selectedResponse = len(m.toolResponses) - 1 // Point to newest response
		}
		m.error = "" // Clear any previous errors
		return m, nil

	case SessionAttachedMsg:
		// Successfully attached to session
		m.attachedSession = &msg.Session
		m.sessionSocket = msg.Socket
		m.sessionMessages = []LoggedMessage{} // Clear previous messages
		m.sessionScroll = 0
		m.state = StateSessionViewer
		m.error = "" // Clear any previous errors
		// Start listening for messages from the session
		return m, m.listenToSession()

	case SessionMessageMsg:
		// New message received from attached session
		m.sessionMessages = append(m.sessionMessages, msg.message)
		// Auto-scroll to bottom (latest message)
		if len(m.sessionMessages) > 20 { // Keep last 100 messages for performance
			m.sessionMessages = m.sessionMessages[1:]
		}
		return m, m.listenToSession() // Continue listening

	case ErrorMsg:
		m.error = msg.err.Error()
		m.loading = false
		m.toolState = ToolStateError
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
			// Initialize tool layout
			m.toolLayout.totalHeight = m.height
			m.toolLayout.paramScroll = 0
			m.toolLayout.responseScroll = 0
			tool := m.tools[m.selectedTool]
			m.calculateToolLayout(tool)
			// Reset tool state
			m.toolState = ToolStateIdle
			m.currentResponse = nil
			// Generate form from tool schema
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
		case "+":
			// Increase parameter pane size
			if m.toolLayout.paramRatio < 0.8 {
				m.toolLayout.paramRatio += 0.1
				if len(m.tools) > 0 {
					m.calculateToolLayout(m.tools[m.selectedTool])
				}
			}
		case "-":
			// Decrease parameter pane size (increase response pane)
			if m.toolLayout.paramRatio > 0.2 {
				m.toolLayout.paramRatio -= 0.1
				if len(m.tools) > 0 {
					m.calculateToolLayout(m.tools[m.selectedTool])
				}
			}
		case "ctrl+up":
			// Scroll parameters up
			if m.toolLayout.paramScroll > 0 {
				m.toolLayout.paramScroll--
			}
		case "ctrl+down":
			// Scroll parameters down
			maxParamScroll := max(0, len(m.formState.Fields)-m.toolLayout.paramHeight+2)
			if m.toolLayout.paramScroll < maxParamScroll {
				m.toolLayout.paramScroll++
			}
		case "shift+up":
			// Scroll responses up
			if m.toolLayout.responseScroll > 0 {
				m.toolLayout.responseScroll--
			}
		case "shift+down":
			// Scroll responses down
			responseLines := 1 // Will calculate based on current response content
			if m.currentResponse != nil && m.currentResponse.PrettyResult != "" {
				responseLines = len(strings.Split(m.currentResponse.PrettyResult, "\n")) + 2
			}
			maxResponseScroll := max(0, responseLines-m.toolLayout.responseHeight+1)
			if m.toolLayout.responseScroll < maxResponseScroll {
				m.toolLayout.responseScroll++
			}
		case "left", "h":
			// Navigate to previous response in history
			if len(m.toolResponses) > 0 && m.selectedResponse > 0 {
				m.selectedResponse--
				m.currentResponse = &m.toolResponses[m.selectedResponse]
				m.toolLayout.responseScroll = 0 // Reset scroll
			}
		case "right", "l":
			// Navigate to next response in history
			if len(m.toolResponses) > 0 && m.selectedResponse < len(m.toolResponses)-1 {
				m.selectedResponse++
				m.currentResponse = &m.toolResponses[m.selectedResponse]
				m.toolLayout.responseScroll = 0 // Reset scroll
			}
		case "ctrl+r":
			// Clear response history
			m.toolResponses = make([]ToolResponse, 0)
			m.currentResponse = nil
			m.selectedResponse = 0
			m.toolState = ToolStateIdle
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

func (m Model) updateSessionList(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		return m, tea.Quit
	case "up", "k":
		if m.selectedSession > 0 {
			m.selectedSession--
		}
	case "down", "j":
		if m.selectedSession < len(m.sessions)-1 {
			m.selectedSession++
		}
	case "enter":
		// Attach to selected session
		if len(m.sessions) > 0 {
			return m, m.attachToSession(m.sessions[m.selectedSession])
		}
	case "r":
		// Refresh session list
		registry := NewSessionRegistryWithPath(m.sessionsDir)
		if err := registry.cleanupDeadSessions(); err != nil {
			m.error = fmt.Sprintf("Failed to cleanup dead sessions: %v", err)
			return m, nil
		}
		
		sessions, err := registry.listSessions()
		if err != nil {
			m.error = fmt.Sprintf("Failed to load sessions: %v", err)
			return m, nil
		}
		
		m.sessions = sessions
		// Adjust selection if it's out of bounds
		if m.selectedSession >= len(m.sessions) {
			m.selectedSession = max(0, len(m.sessions)-1)
		}
		m.error = "" // Clear any previous errors
	}
	return m, nil
}

func (m Model) updateSessionViewer(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		// Close socket connection before quitting
		if m.sessionSocket != nil {
			m.sessionSocket.Close()
		}
		return m, tea.Quit
	case "esc":
		// Detach from session and return to session list
		if m.sessionSocket != nil {
			m.sessionSocket.Close()
			m.sessionSocket = nil
		}
		m.attachedSession = nil
		m.sessionMessages = []LoggedMessage{}
		m.state = StateSessionList
		// Refresh session list when returning
		registry := NewSessionRegistryWithPath(m.sessionsDir)
		if err := registry.cleanupDeadSessions(); err == nil {
			if sessions, err := registry.listSessions(); err == nil {
				m.sessions = sessions
			}
		}
	case "up", "k":
		// Scroll up in messages
		if m.sessionScroll > 0 {
			m.sessionScroll--
		}
	case "down", "j":
		// Scroll down in messages
		maxScroll := max(0, len(m.sessionMessages)-20) // Visible area
		if m.sessionScroll < maxScroll {
			m.sessionScroll++
		}
	case "g":
		// Go to top
		m.sessionScroll = 0
	case "G":
		// Go to bottom (latest messages)
		m.sessionScroll = max(0, len(m.sessionMessages)-20)
	}
	return m, nil
}

func (m Model) listenToSession() tea.Cmd {
	if m.sessionSocket == nil {
		return nil
	}
	
	return func() tea.Msg {
		// Read from socket with timeout
		buf := make([]byte, 4096)
		n, err := m.sessionSocket.Read(buf)
		if err != nil {
			return ErrorMsg{fmt.Errorf("session disconnected: %v", err)}
		}
		
		// Parse the received data as a logged message
		var loggedMsg LoggedMessage
		if err := json.Unmarshal(buf[:n], &loggedMsg); err != nil {
			// If JSON parsing fails, create a raw message
			loggedMsg = LoggedMessage{
				Content:   buf[:n],
				Timestamp: time.Now(),
				Direction: DirectionInbound, // Messages from proxy are inbound to us
			}
		}
		
		return SessionMessageMsg{message: loggedMsg}
	}
}

func (m Model) attachToSession(session ProxySession) tea.Cmd {
	return func() tea.Msg {
		// Check if session is still alive
		registry := NewSessionRegistryWithPath(m.sessionsDir)
		if !registry.isProcessAlive(session.PID) {
			return ErrorMsg{fmt.Errorf("session '%s' is no longer active", session.Name)}
		}
		
		// Connect to the session's Unix socket
		conn, err := net.Dial("unix", session.SocketPath)
		if err != nil {
			return ErrorMsg{fmt.Errorf("failed to connect to session socket: %v", err)}
		}
		
		return SessionAttachedMsg{Session: session, Socket: conn}
	}
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
	return tea.Sequence(
		func() tea.Msg {
			return ToolExecutionStartMsg{}
		},
		func() tea.Msg {
			if len(m.tools) == 0 {
				return ErrorMsg{fmt.Errorf("no tools available")}
			}

			tool := m.tools[m.selectedTool]
			args := buildArgumentsFromForm(m.formState.Fields)
			
			startTime := time.Now()
			resp, err := m.client.CallTool(tool.Name, args)
			executionTime := time.Since(startTime)
			
			if err != nil {
				return ErrorMsg{err}
			}

			// Create tool response
			toolResp := ToolResponse{
				ToolName:      tool.Name,
				Timestamp:     time.Now(),
				Arguments:     args,
				ExecutionTime: executionTime,
			}

			if resp.Result != nil {
				// Success response
				toolResp.Success = true
				toolResp.Result = resp.Result
				
				// Pretty print the result
				if resultBytes, err := json.MarshalIndent(resp.Result, "", "  "); err == nil {
					toolResp.PrettyResult = string(resultBytes)
				} else {
					toolResp.PrettyResult = fmt.Sprintf("%+v", resp.Result)
				}
			} else if resp.Error != nil {
				// Error response
				toolResp.Success = false
				toolResp.Error = resp.Error.Message
				
				if resp.Error.Data != nil {
					if dataBytes, err := json.MarshalIndent(resp.Error.Data, "", "  "); err == nil {
						toolResp.PrettyResult = fmt.Sprintf("Error: %s\nData:\n%s", resp.Error.Message, string(dataBytes))
					} else {
						toolResp.PrettyResult = fmt.Sprintf("Error: %s\nData: %+v", resp.Error.Message, resp.Error.Data)
					}
				} else {
					toolResp.PrettyResult = fmt.Sprintf("Error: %s", resp.Error.Message)
				}
			} else {
				// Empty response
				toolResp.Success = true
				toolResp.Result = nil
				toolResp.PrettyResult = "(No response data)"
			}
			
			return ToolResponseMsg{response: toolResp}
		},
	)
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
		// Calculate layout for three panes
		m.calculateToolLayout(tool)
		
		// === TOP PANE: Tool Info (Dynamic Height) ===
		s := styles.title.Render("Tool: " + tool.Name)
		
		// Wrap and display description
		descLines := wrapText(tool.Description, m.width-4)
		for _, line := range descLines {
			s += "\n" + styles.normal.Render(line)
		}
		
		// Add padding to reach calculated info height
		currentLines := strings.Count(s, "\n") + 1
		for currentLines < m.toolLayout.infoHeight-1 {
			s += "\n"
			currentLines++
		}
		
		s += "\n" + strings.Repeat("─", m.width) // Separator
		
		// === MIDDLE PANE: Parameters (Scrollable) ===
		s += "\n" + styles.header.Render("Parameters:")
		
		if len(m.formState.Fields) == 0 {
			s += "\n" + styles.normal.Render("No parameters required")
		} else {
			// Calculate visible parameter range
			startIdx := m.toolLayout.paramScroll
			endIdx := min(startIdx+m.toolLayout.paramHeight-1, len(m.formState.Fields))
			
			for i := startIdx; i < endIdx; i++ {
				field := m.formState.Fields[i]
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
				
				// Show description if available (only for selected field to save space)
				if field.Description != "" && i == m.formState.CurrentField {
					s += "\n" + styles.normal.Copy().Faint(true).Render("    " + field.Description)
				}
				
				// Show options for enum fields (only for selected field)
				if len(field.Options) > 0 && i == m.formState.CurrentField {
					s += "\n" + styles.normal.Copy().Faint(true).Render("    Options: " + strings.Join(field.Options, ", "))
				}
			}
			
			// Show scroll indicators
			if startIdx > 0 {
				s += "\n" + styles.normal.Copy().Faint(true).Render("↑ More parameters above (Ctrl+Up to scroll)")
			}
			if endIdx < len(m.formState.Fields) {
				s += "\n" + styles.normal.Copy().Faint(true).Render("↓ More parameters below (Ctrl+Down to scroll)")
			}
		}
		
		// Fill remaining parameter pane space
		currentParamLines := strings.Count(s[strings.LastIndex(s, "─"):], "\n")
		for currentParamLines < m.toolLayout.paramHeight+m.toolLayout.infoHeight {
			s += "\n"
			currentParamLines++
		}
		
		s += strings.Repeat("─", m.width) // Separator

		// === BOTTOM PANE: Tool Response (Scrollable) ===
		responseHeader := "Tool Response:"
		if len(m.toolResponses) > 0 {
			responseHeader = fmt.Sprintf("Tool Response (%d/%d):", m.selectedResponse+1, len(m.toolResponses))
		}
		s += "\n" + styles.header.Render(responseHeader)
		
		switch m.toolState {
		case ToolStateLoading:
			s += "\n" + styles.loading.Render("Executing tool...")
		case ToolStateSuccess, ToolStateError:
			if m.currentResponse != nil {
				// Response metadata header
				statusStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("2")) // Green
				statusIcon := "✓"
				if !m.currentResponse.Success {
					statusStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("1")) // Red
					statusIcon = "✗"
				}
				
				timestamp := m.currentResponse.Timestamp.Format("15:04:05")
				duration := fmt.Sprintf("%.2fms", float64(m.currentResponse.ExecutionTime.Nanoseconds())/1000000)
				status := "Success"
				if !m.currentResponse.Success {
					status = "Error"
				}
				
				metadata := fmt.Sprintf("%s %s | %s | %s", statusIcon, status, timestamp, duration)
				s += "\n" + statusStyle.Render(metadata)
				
				// Show arguments if any
				if len(m.currentResponse.Arguments) > 0 {
					argStr := "Args: "
					argParts := make([]string, 0, len(m.currentResponse.Arguments))
					for k, v := range m.currentResponse.Arguments {
						argParts = append(argParts, fmt.Sprintf("%s=%v", k, v))
					}
					argStr += strings.Join(argParts, ", ")
					if len(argStr) > 60 {
						argStr = argStr[:57] + "..."
					}
					s += "\n" + styles.normal.Copy().Faint(true).Render(argStr)
				}
				
				s += "\n" // Separator
				
				// Show scrollable response content
				responseLines := strings.Split(m.currentResponse.PrettyResult, "\n")
				startIdx := m.toolLayout.responseScroll
				endIdx := min(startIdx+m.toolLayout.responseHeight-6, len(responseLines)) // Reserve space for metadata
				
				for i := startIdx; i < endIdx; i++ {
					line := responseLines[i]
					// Apply syntax highlighting for JSON-like content
					if strings.TrimSpace(line) != "" {
						if strings.Contains(line, ":") && (strings.Contains(line, "{") || strings.Contains(line, "}")) {
							// JSON structure - use subtle highlighting
							s += "\n" + styles.normal.Copy().Foreground(lipgloss.Color("6")).Render(line)
						} else if strings.HasPrefix(strings.TrimSpace(line), "\"" ) {
							// String values - green
							s += "\n" + styles.normal.Copy().Foreground(lipgloss.Color("2")).Render(line)
						} else {
							s += "\n" + styles.normal.Render(line)
						}
					} else {
						s += "\n"
					}
				}
				
				// Show scroll indicators for response
				if startIdx > 0 || endIdx < len(responseLines) {
					scrollInfo := ""
					if startIdx > 0 {
						scrollInfo += "↑ "
					}
					scrollInfo += fmt.Sprintf("[%d-%d/%d]", startIdx+1, min(endIdx, len(responseLines)), len(responseLines))
					if endIdx < len(responseLines) {
						scrollInfo += " ↓"
					}
					s += "\n" + styles.normal.Copy().Faint(true).Render(scrollInfo)
				}
				
				// Navigation hints
				if len(m.toolResponses) > 1 {
					navHint := "← Previous response | Next response →"
					s += "\n" + styles.normal.Copy().Faint(true).Render(navHint)
				}
			} else if m.error != "" {
				s += "\n" + styles.error.Render("✗ Error: " + m.error)
			}
		case ToolStateIdle:
			s += "\n" + styles.normal.Copy().Faint(true).Render("Press T to test this tool")
			if len(m.toolResponses) > 0 {
				s += "\n" + styles.normal.Copy().Faint(true).Render(fmt.Sprintf("Previous results: %d executions (use ← → to browse)", len(m.toolResponses)))
			}
		}

		// Instructions at the bottom
		if m.formState.Mode == FormModeEdit {
			s += "\n\n" + "Editing field. Type to enter value, Enter to save, Esc to cancel"
		} else {
			basicControls := "↑/↓ navigate, Enter/E edit, T test, +/- resize panes"
			scrollControls := "Ctrl+↑↓ scroll params, Shift+↑↓ scroll response"
			historyControls := "←/→ browse history, Ctrl+R clear history"
			s += "\n\n" + basicControls + "\n" + scrollControls + "\n" + historyControls + ", Esc back"
		}

		// Only show system errors here (not tool responses)
		if m.error != "" && m.toolState != ToolStateError {
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

	case StateSessionList:
		s := styles.title.Render("Active MCP Proxy Sessions")
		s += "\n" + styles.header.Render("Select a session to attach and inspect:")
		
		if m.loading {
			s += "\n" + styles.loading.Render("Loading sessions...")
		} else if len(m.sessions) == 0 {
			s += "\n\n" + styles.normal.Render("No active proxy sessions found.")
			s += "\n" + styles.normal.Copy().Faint(true).Render("Start a proxy session with: mcpview --proxy --session <name> --target \"<command>\"")
		} else {
			s += "\n\nSessions:"
			for i, session := range m.sessions {
				style := styles.normal
				if i == m.selectedSession {
					style = styles.selected
				}
				
				// Status indicator
				statusIcon := "●"
				statusColor := "2" // Green for alive
				if !NewSessionRegistryWithPath(m.sessionsDir).isProcessAlive(session.PID) {
					statusIcon = "○"
					statusColor = "1" // Red for dead
				}
				statusStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(statusColor))
				
				// Format session info
				duration := time.Since(session.StartTime).Truncate(time.Second)
				sessionLine := fmt.Sprintf("  %s %s", statusIcon, session.Name)
				sessionLine += fmt.Sprintf(" | %s | %s", session.TargetCmd, duration)
				if session.MessageCount > 0 {
					sessionLine += fmt.Sprintf(" | %d msgs", session.MessageCount)
				}
				
				s += "\n" + style.Render(sessionLine)
				
				// Show additional details for selected session
				if i == m.selectedSession {
					details := fmt.Sprintf("    PID: %d | Started: %s", 
						session.PID, 
						session.StartTime.Format("15:04:05"))
					if !session.LastActivity.IsZero() {
						details += fmt.Sprintf(" | Last activity: %s", 
							session.LastActivity.Format("15:04:05"))
					}
					s += "\n" + statusStyle.Render(details)
				}
			}
		}
		
		s += "\n\n" + "↑/↓ navigate, Enter attach, R refresh, Q quit"
		
		if m.error != "" {
			s += "\n" + styles.error.Render("Error: "+m.error)
		}
		return s

	case StateSessionViewer:
		if m.attachedSession == nil {
			return "No session attached"
		}
		
		s := styles.title.Render(fmt.Sprintf("Session Viewer: %s", m.attachedSession.Name))
		s += "\n" + styles.header.Render(fmt.Sprintf("Target: %s | PID: %d", m.attachedSession.TargetCmd, m.attachedSession.PID))
		
		// Status indicator
		registry := NewSessionRegistryWithPath(m.sessionsDir)
		statusIcon := "●"
		statusColor := "2" // Green
		if !registry.isProcessAlive(m.attachedSession.PID) {
			statusIcon = "○"
			statusColor = "1" // Red
		}
		statusStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(statusColor))
		s += "\n" + statusStyle.Render(fmt.Sprintf("%s Session Status: %s", statusIcon, 
			map[bool]string{true: "Active", false: "Disconnected"}[registry.isProcessAlive(m.attachedSession.PID)]))
		
		s += "\n" + strings.Repeat("─", m.width)
		
		// Live messages
		s += "\n" + styles.header.Render(fmt.Sprintf("Live Messages (%d total):", len(m.sessionMessages)))
		
		if len(m.sessionMessages) == 0 {
			s += "\n" + styles.normal.Render("No messages yet... waiting for MCP communication")
		} else {
			// Show scrollable messages
			visibleLines := m.height - 8 // Reserve space for header and controls
			startIdx := m.sessionScroll
			endIdx := min(startIdx+visibleLines, len(m.sessionMessages))
			
			for i := startIdx; i < endIdx; i++ {
				msg := m.sessionMessages[i]
				
				// Direction and timestamp
				direction := "→"
				color := "blue"
				if msg.Direction == DirectionInbound {
					direction = "←"
					color = "green"
				}
				
				timestamp := msg.Timestamp.Format("15:04:05.000")
				msgStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(color))
				
				// Show message content (truncated for display)
				content := string(msg.Content)
				if len(content) > 100 {
					content = content[:97] + "..."
				}
				
				s += "\n" + msgStyle.Render(fmt.Sprintf("%s %s %s", direction, timestamp, content))
			}
			
			// Show scroll indicators
			if startIdx > 0 || endIdx < len(m.sessionMessages) {
				scrollInfo := fmt.Sprintf("[%d-%d/%d]", startIdx+1, endIdx, len(m.sessionMessages))
				if startIdx > 0 {
					scrollInfo = "↑ " + scrollInfo
				}
				if endIdx < len(m.sessionMessages) {
					scrollInfo += " ↓"
				}
				s += "\n" + styles.normal.Copy().Faint(true).Render(scrollInfo)
			}
		}
		
		s += "\n\n" + "↑/↓ scroll messages, G top, Shift+G bottom, Esc detach, Q quit"
		
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
	proxyMode := flag.Bool("proxy", false, "Start in stdio proxy mode")
	targetCmd := flag.String("target", "", "Target MCP server command for proxy mode")
	sessionName := flag.String("session", "", "Session name for proxy mode")
	listSessions := flag.Bool("list-sessions", false, "List active proxy sessions and exit")
	sessionsDir := flag.String("sessions-dir", "/tmp/mcpview-sessions", "Directory to store session metadata")
	attachMode := flag.Bool("attach", false, "Show session list for attaching to running sessions")
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
		fmt.Fprintf(os.Stderr, "  %s --proxy --target \"python srv.py\" # Stdio proxy mode\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --proxy --target \"python srv.py\" --session \"myapi\" # Named proxy session\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --sessions-dir ./sessions --list-sessions # Use local sessions directory\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --attach # Show interactive session list for debugging\n", os.Args[0])
	}
	flag.Parse()
	
	// Handle session listing
	if *listSessions {
		registry := NewSessionRegistryWithPath(*sessionsDir)
		
		// Clean up dead sessions first
		if err := registry.cleanupDeadSessions(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to cleanup dead sessions: %v\n", err)
		}
		
		// List remaining sessions
		sessions, err := registry.listSessions()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error listing sessions: %v\n", err)
			os.Exit(1)
		}
		
		if len(sessions) == 0 {
			fmt.Println("No active proxy sessions")
		} else {
			fmt.Printf("Active proxy sessions (%d):\n", len(sessions))
			for _, session := range sessions {
				alive := "✓"
				if !registry.isProcessAlive(session.PID) {
					alive = "✗"
				}
				duration := time.Since(session.StartTime).Truncate(time.Second)
				lastSeen := time.Since(session.LastActivity).Truncate(time.Second)
				fmt.Printf("  %s %s\n", alive, session.Name)
				fmt.Printf("    Command: %s\n", session.TargetCmd)
				fmt.Printf("    PID: %d\n", session.PID)
				fmt.Printf("    Running: %v\n", duration)
				fmt.Printf("    Last activity: %v ago\n", lastSeen)
				fmt.Printf("    Messages: %d\n", session.MessageCount)
				fmt.Println()
			}
		}
		return
	}
	
	// Handle attach mode - start TUI with session list
	if *attachMode {
		model := NewModel()
		model.state = StateSessionList
		model.sessionsDir = *sessionsDir
		
		// Load initial sessions
		registry := NewSessionRegistryWithPath(*sessionsDir)
		if err := registry.cleanupDeadSessions(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to cleanup dead sessions: %v\n", err)
		}
		
		sessions, err := registry.listSessions()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading sessions: %v\n", err)
			os.Exit(1)
		}
		
		model.sessions = sessions
		model.selectedSession = 0
		
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		
		p := tea.NewProgram(&model, tea.WithAltScreen())
		
		go func() {
			<-ctx.Done()
			p.Quit()
		}()
		
		if _, err := p.Run(); err != nil {
			log.Fatal(err)
		}
		return
	}
	
	// Validate proxy mode arguments
	if *proxyMode && *targetCmd == "" {
		fmt.Fprintf(os.Stderr, "Error: --target is required when using --proxy mode\n")
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	model := NewModel()
	
	// Handle stdio proxy mode - this runs without TUI
	if *proxyMode {
		var proxy *StdioProxy
		if *sessionName != "" {
			proxy = NewStdioProxyWithSessionAndDir(*targetCmd, *sessionName, *sessionsDir)
		} else {
			proxy = NewStdioProxy(*targetCmd)
		}
		if err := proxy.RunProxy(); err != nil {
			log.Fatalf("Stdio proxy error: %v", err)
		}
		return
	}
	
	// Set initial state based on flags for TUI modes
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