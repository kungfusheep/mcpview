# MCP Explorer

**A terminal UI for developing, debugging, and testing MCP (Model Context Protocol) servers.**

Live message monitoring • Tool testing with dynamic forms • Transparent proxy mode • Response history

## Features

- 🔍 **Debug Mode** - Live message monitoring with split-pane interface
- 🛠️ **Tool Testing** - Dynamic parameter forms generated from JSON schemas  
- 🔄 **Proxy Mode** - Transparent stdio proxy for inspecting any MCP communication
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

### Explorer Mode (Direct Connection)
```bash
# Connect directly to an MCP server
mcpview --server "python my_server.py"

# Debug mode with live message monitoring
mcpview --debug --server "npx @modelcontextprotocol/server-filesystem /"
```

### Proxy Mode (Transparent Debugging)
```bash
# Use mcpview as a transparent proxy
mcpview --proxy --target "python server.py"

# Then configure your MCP client to use mcpview instead of the server
```

### Interactive Mode
```bash
# Start with connection prompt
mcpview
```

**Key Controls:** `↑↓/jk` navigate • `Enter` select • `t` test tool • `r` resources • `m` messages • `d` debug • `q` quit

## What is MCP?

[Model Context Protocol](https://modelcontextprotocol.io) enables applications to provide context to LLMs in a standardized way. MCP Explorer helps you develop and debug MCP servers by providing visibility into the protocol communication.

## License

Apache License 2.0 - see [LICENSE](LICENSE) for details.
