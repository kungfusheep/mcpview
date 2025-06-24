# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MCP Explorer (`mcpview`) is a comprehensive terminal UI application for developing, debugging, and working with MCP (Model Context Protocol) servers. It's designed to be an "all singing all dancing" tool for MCP development workflows, written in Go following a single-file architecture pattern.

## Build and Run Commands

```bash
# Build the application
go build -o mcpview .

# Run in explorer mode (default)
./mcpview

# Run in debug mode with live message pane
./mcpview --debug

# Run in stdio proxy mode
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

## Development Roadmap

### Phase 1: Enhanced Core Functionality (Current)
- ✅ Basic MCP client with stdio transport
- ✅ Bubbletea TUI for tool/resource browsing
- ✅ Dynamic form generation from JSON schemas
- ✅ Message logging and history with timestamps
- ✅ JSON pretty-printing with syntax highlighting
- ✅ Debug mode with live message pane
- 🚧 Enhanced error handling and display
- 📋 Parameter presets save/load functionality
- 📋 Resource content viewing and export

### Phase 2: MCP Proxy Mode (Core Feature)
- ✅ Bidirectional proxy between MCP client/server
- ✅ Real-time message interception and logging
- ✅ Live connection monitoring with client details
- ✅ TCP proxy server with automatic MCP server spawning
- 📋 fzf-style filtering and search capabilities
- 📋 Message modification/injection for testing

### Phase 3: Advanced Development Features
- 📋 Multi-server connection management
- 📋 Schema validation and protocol compliance checking
- 📋 Mock client for server testing
- 📋 Performance metrics and load testing
- 📋 Cross-server tool execution

### Phase 4: Integration & Automation
- 📋 Configuration management and templates
- 📋 Scripted test sequences
- 📋 CI/CD integration helpers
- 📋 Advanced filtering with regex and bookmarks

Legend: ✅ Complete | 🚧 In Progress | 📋 Planned

## Architecture

The application follows Pete's Go structure philosophy with everything in a single `mcpview.go` file:

### Current Components
- **MCP Client**: JSON-RPC 2.0 communication over stdio transport
- **Bubbletea TUI**: Multi-state terminal interface
- **Form System**: Dynamic parameter input from JSON schemas
- **Message Handling**: Request/response processing

### Current Application States
- `StateConnection`: Server command input screen
- `StateToolsList`: Browse available MCP tools
- `StateToolDetail`: View tool details and parameter forms
- `StateResourcesList`: Browse available MCP resources
- `StateMessageHistory`: Historical message browser
- `StateDebugMode`: Live debug mode with split-pane message view
- `StateProxyMode`: Proxy server mode with connection monitoring

### Planned Components
- **ProxyManager**: Bidirectional MCP proxy with interception
- **MessageStore**: Persistent message history with search indexing
- **FilterEngine**: Real-time message filtering (fzf-style)
- **ConfigManager**: Save/load configurations and presets
- **ValidationEngine**: Schema and protocol validation
- **PerformanceTracker**: Timing and metrics collection

### Planned Application States
- `StateProxy`: Proxy mode with live message view
- `StateMessageHistory`: Historical message browser with search
- `StateServerManager`: Multi-server dashboard
- `StateConfiguration`: Settings and presets management

## Key Structs

- `MCPClient`: Handles stdio communication with MCP servers
- `Model`: Main Bubbletea model managing application state
- `FormField`/`FormState`: Dynamic parameter input forms
- `JSONSchema`: JSON schema parsing for form generation
- `Tool`/`Resource`: MCP protocol data structures

## Dependencies

### Current
- `github.com/charmbracelet/bubbletea` - Terminal UI framework
- `github.com/charmbracelet/lipgloss` - Terminal styling
- Standard Go libraries for JSON-RPC, exec, and I/O

### Planned Additions
- `github.com/sahilm/fuzzy` - fzf-style filtering
- `github.com/alecthomas/chroma` - Syntax highlighting
- `github.com/spf13/viper` - Configuration management
- `go.etcd.io/bbolt` - Embedded database for message history

## MCP Server Testing

The application connects to MCP servers via stdio transport. Common test commands:
- `python my_mcp_server.py`
- `node server.js`  
- `./my-server --stdio`

## Development Modes

### Explorer Mode (Current)
Direct connection to MCP servers for tool/resource exploration and testing.

### Debug Mode (Current)
Live debugging interface with split-pane layout:
- **Top Pane**: Real-time message stream showing all MCP traffic
- **Bottom Pane**: Tools list for testing while monitoring messages
- **Features**: 
  - Live message updates with timestamps
  - Direction indicators (→ outbound, ← inbound)
  - Scrollable message history
  - Resizable panes (+/- keys)
  - Tool testing while watching traffic
  - Compact message display with method/response info

### Proxy Mode (Current)
Stdio-based transparent proxy between MCP client and server:
```bash
# Use mcpview as an MCP server that proxies to the real server
./mcpview --proxy --target "python server.py"

# MCP client spawns mcpview instead of the real server
# All messages flow through mcpview for inspection
```

**Features:**
- Stdio transport proxy (proper MCP protocol)
- Transparent message forwarding between client and target server
- Real-time message interception and logging
- Works with any MCP client (Claude desktop, MCP libraries, etc.)
- Automatic target server process management
- Full message visibility without client changes

## Development Notes

- Single file architecture maintained - all code in `mcpview.go`
- Uses Go 1.24.0
- No external build tools or Makefile required
- Supports all JSON schema types: string, number, boolean, array, object
- Message history stored in embedded database for persistence
- Real-time filtering capabilities for large message volumes
- Configuration profiles for different MCP servers and workflows