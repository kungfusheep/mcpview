# MCP Explorer

A terminal UI application for exploring MCP (Model Context Protocol) servers, written in Go.

## Features

- Connect to MCP servers via stdio transport
- Browse available tools and their schemas
- Test tool invocations
- Explore server resources
- Interactive terminal UI with keyboard navigation

## Usage

```bash
go build -o mcpview .
./mcpview
```

The application will start in connection mode where you can enter an MCP server command.

### Example MCP Server Commands

```bash
# Python MCP server
python my_mcp_server.py

# Node.js MCP server  
node server.js

# Any executable that implements MCP stdio transport
./my-server --stdio
```

## Navigation

### Connection Screen
- Type your MCP server command
- Press Enter to connect
- Ctrl+C or Q to quit

### Tools List
- ↑/↓ or K/J to navigate tools
- Enter to view tool details and schema
- R to view resources
- C to reconnect to a different server
- Q to quit

### Tool Details
- View tool name, description, and dynamically generated parameter form
- ↑/↓ or K/J to navigate between parameters
- Enter or E to edit a parameter value
- T to test the tool with current parameter values
- Esc to go back
- Q to quit

### Parameter Editing
- Type to enter value for the selected parameter
- Enter to save the value
- Esc to cancel editing
- Supports different field types: string, number, boolean, array, object
- Shows field descriptions and enum options where available
- Required fields are marked with *

### Resources List
- ↑/↓ or K/J to navigate resources
- Esc to go back to tools
- Q to quit

## MCP Protocol Support

The application implements the core MCP protocol methods:

- `initialize` - Server initialization and capability negotiation
- `tools/list` - Discover available tools
- `tools/call` - Invoke tools with arguments
- `resources/list` - List available resources

## Architecture

Following Pete's Go structure philosophy, the entire application is contained in a single `mcpview.go` file with:

- Main entry point with `func main()`
- MCP client implementation using stdio transport
- Bubbletea TUI models and views
- JSON-RPC 2.0 message handling
- All application logic in one discoverable location

The code is structured with clear separation using structs and methods for encapsulation while keeping everything in one file for easy understanding and debugging.