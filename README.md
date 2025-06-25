# MCP Explorer

**A terminal UI for developing, debugging, and testing MCP (Model Context Protocol) servers.**

Session-based proxy debugging • Live message monitoring • Tool testing with dynamic forms • Message persistence

## Features

- 🔄 **Session Management** - Persistent proxy sessions for debugging any MCP setup
- 🔗 **Attach Mode** - Connect to running proxy sessions for live debugging
- 🛠️ **Tool Testing** - Dynamic parameter forms generated from JSON schemas  
- 🔍 **Debug Mode** - Live message monitoring with split-pane interface
- 💾 **Message Persistence** - Session history preserved across connections
- 📊 **Response History** - Navigate through execution history with syntax highlighting
- ⚡ **Real-time** - Watch MCP traffic flow in real-time with timestamps

## Installation

```bash
go install github.com/kungfusheep/mcpview@latest
```

Or build from source:
```bash
git clone https://github.com/kungfusheep/mcpview
cd mcpview
go build -o mcpview .
```

## Usage

### Quick Start (Direct Connection)
```bash
# Interactive mode with connection prompt
mcpview

# Connect directly to an MCP server for testing
mcpview --server "python my_server.py"

# Debug mode with live message monitoring
mcpview --debug --server "npx @modelcontextprotocol/server-filesystem /"
```

### Proxy Debugging Workflow

The most powerful way to debug MCP communication is using proxy sessions:

```bash
# 1. Start a proxy session (creates a session like "aal-swift-0625-1234")
mcpview --proxy --target "python server.py"

# 2. In another terminal, attach to debug the session
mcpview --attach                    # Shows interactive session browser
mcpview --list-sessions            # Lists all active sessions

# 3. Configure your MCP client to connect through the proxy
# Replace "python server.py" with "mcpview --proxy --target 'python server.py'"
```

**Custom Session Management:**
```bash
# Named sessions for easier identification
mcpview --proxy --target "node server.js" --session "myapi"

# Custom session storage directory
mcpview --attach --sessions-dir ./debug-sessions
```

### Key Controls

**Session List:** `↑↓/jk` navigate • `Enter` attach to session • `q` quit

**Session Viewer:** `↑↓/jk` scroll messages • `[/]` scroll detail • `Esc` back to list

**Tool Testing:** `t` test tool • `r` resources • `m` messages • `d` debug mode • `q` quit

## Practical Examples

### Debugging Claude Desktop Integration
```bash
# 1. Start proxy for your MCP server
mcpview --proxy --target "python ~/my-mcp-server/main.py"

# 2. Update Claude Desktop config to use the proxy:
# Change: "command": "python ~/my-mcp-server/main.py"
# To: "command": "mcpview --proxy --target 'python ~/my-mcp-server/main.py'

# 3. Attach to see all Claude ↔ Server communication
mcpview --attach
```

### Testing During Development
```bash
# Direct connection for quick tool testing
mcpview --server "python my_server.py"

# Debug mode to see protocol messages while testing
mcpview --debug --server "npx @modelcontextprotocol/server-filesystem /Users/me/docs"
```

### Multi-Server Debugging
```bash
# Start multiple proxy sessions
mcpview --proxy --target "python db_server.py"
mcpview --proxy --target "node fs_server.js"

# Attach to debug any session
mcpview --attach    # Choose which session to inspect
```

## What is MCP?

[Model Context Protocol](https://modelcontextprotocol.io) enables applications to provide context to LLMs in a standardized way. MCP Explorer helps you develop and debug MCP servers by providing visibility into the protocol communication.

## License

Apache License 2.0 - see [LICENSE](LICENSE) for details.
