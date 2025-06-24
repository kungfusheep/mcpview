# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MCP Explorer (`mcpview`) is a terminal UI application for developing and debugging MCP (Model Context Protocol) servers. Written in Go following a single-file architecture pattern, it provides both interactive exploration and headless proxy functionality.

## Build and Run Commands

```bash
# Build the application
go build -o mcpview .

# Run in explorer mode (default)
./mcpview

# Run in debug mode with live message pane
./mcpview --debug

# Run in stdio proxy mode (headless - no TUI)
./mcpview --proxy --target "python server.py"

# Auto-connect to MCP server
./mcpview --server "python my_server.py"

# Debug mode with auto-connect
./mcpview --debug --server "node server.js"

# Show help
./mcpview --help

# Run directly without building
go run .

# Install dependencies
go mod tidy

# Format code
go fmt .

# Vet code for issues
go vet .
```

## Current Features

### Core MCP Client
- ✅ JSON-RPC 2.0 communication over stdio transport
- ✅ MCP protocol initialization and tool/resource discovery
- ✅ Dynamic form generation from JSON schemas (string, number, boolean, array, object)
- ✅ Tool execution with parameter validation
- ✅ Message logging with timestamps and direction tracking

### Terminal UI (Bubbletea)
- ✅ Connection screen for server command input
- ✅ Tools list browser with navigation
- ✅ Tool detail view with three-pane layout:
  - Tool info (dynamic height based on description)
  - Parameter form (scrollable, resizable)
  - Response viewer (scrollable, with execution history)
- ✅ Resources list browser
- ✅ Message history viewer with pretty-printed JSON
- ✅ Debug mode with split-pane layout (messages top, tools bottom)

### Stdio Proxy Mode
- ✅ Headless transparent proxy between MCP client and server
- ✅ Message interception and logging
- ✅ Automatic target server process management
- ✅ Works with any MCP client (Claude Desktop, etc.)

## Architecture

Single file `mcpview.go` containing:

### Application States
- `StateConnection`: Server command input screen
- `StateToolsList`: Browse available MCP tools  
- `StateToolDetail`: View tool details and parameter forms
- `StateResourcesList`: Browse available MCP resources
- `StateMessageHistory`: Historical message browser
- `StateDebugMode`: Live debug mode with split-pane message view

### Key Structs
- `MCPClient`: Handles stdio communication with MCP servers
- `Model`: Main Bubbletea model managing application state
- `FormField`/`FormState`: Dynamic parameter input forms
- `JSONSchema`: JSON schema parsing for form generation
- `Tool`/`Resource`: MCP protocol data structures
- `StdioProxy`: Headless proxy functionality
- `ToolLayout`/`DebugLayout`: UI layout management

## Dependencies

- `github.com/charmbracelet/bubbletea` - Terminal UI framework
- `github.com/charmbracelet/lipgloss` - Terminal styling
- Standard Go libraries for JSON-RPC, exec, and I/O

## Usage Patterns

### Interactive Mode
1. Start `./mcpview`
2. Enter MCP server command (e.g., `python server.py`)
3. Browse tools, edit parameters, execute with real-time feedback
4. Use debug mode (`d` key) for live message monitoring

### Proxy Mode (Headless)
```bash
# Replace your MCP server in client config with:
./mcpview --proxy --target "python your_real_server.py"

# All messages flow through mcpview for logging/inspection
# No TUI - pure stdio forwarding
```

### Debug Workflow
```bash
# Start in debug mode with auto-connect
./mcpview --debug --server "python server.py"

# Top pane: Live message stream
# Bottom pane: Tools for testing
# Test tools while watching all MCP traffic
```

## Roadmap

### Immediate Improvements
- 📋 Enhanced error handling and display
- 📋 Resource content viewing
- 📋 Parameter presets save/load
- 📋 Message search and filtering
- 📋 Configuration file support

### Future Features  
- 📋 Multi-server connection management
- 📋 Schema validation and protocol compliance checking
- 📋 Performance metrics and timing
- 📋 Message modification/injection for testing
- 📋 Export functionality (logs, responses)

### Advanced Goals
- 📋 TCP proxy mode with connection monitoring UI
- 📋 Mock client for server testing
- 📋 Cross-server tool execution
- 📋 CI/CD integration helpers

## Development Notes

- Single file architecture maintained - all code in `mcpview.go`
- No external build tools or Makefile required
- Message history kept in memory (no persistence yet)
- Proxy mode is completely separate from TUI - runs headless
- Form system supports all JSON schema primitives
- Real-time message updates use Bubbletea's messaging system