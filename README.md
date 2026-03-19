# MCP-Jumal — Junior Malware Analyst

An MCP (Model Context Protocol) server for automated basic static malware analysis. It exposes analysis capabilities to LLM clients (e.g. Claude Desktop) while keeping all file processing isolated inside a Docker container.

## Architecture

```
┌─────────────────────────────┐        ┌──────────────────────────────────┐
│        Host Machine         │        │        Docker Container           │
│                             │        │                                  │
│  LLM Client (Claude etc.)   │        │   Analysis Worker (FastAPI)      │
│         │  stdio            │        │                                  │
│         ▼                   │  HTTP  │  POST /api/v1/triage             │
│   bridge/bridge.py  ────────┼───────►│  POST /api/v1/pe-info            │
│   (FastMCP server)          │        │  POST /api/v1/yara               │
│                             │        │  POST /api/v1/strings            │
└─────────────────────────────┘        │                                  │
                                       │  Reads from /samples (read-only) │
                                       │  Reads from /rules   (read-only) │
                                       └──────────────────────────────────┘
```

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/)
- Python 3.11+
- [Claude Desktop](https://claude.ai/download) or another MCP-compatible client
- (Optional) A [VirusTotal API key](https://www.virustotal.com/gui/my-apikey) for the `check_virustotal` tool

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/dyussekeyev/jumal-mcp.git
cd jumal-mcp
```

### 2. Prepare directories

```bash
mkdir -p malware_samples yara_rules
# Place malware samples in malware_samples/
# Place YARA rule files (*.yar or *.yara) in yara_rules/
```

### 3. Start the analysis worker

```bash
docker compose up -d
```

### 4. Install bridge dependencies

```bash
pip install fastmcp requests
```

### 5. Configure Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or the equivalent on your OS, and add:

```json
{
  "mcpServers": {
    "jumal-analyzer": {
      "command": "python",
      "args": ["/path/to/jumal-mcp/bridge/bridge.py"],
      "env": {
        "VT_API_KEY": "YOUR_VIRUSTOTAL_API_KEY",
        "WORKER_URL": "http://localhost:8000/api/v1"
      }
    }
  }
}
```

Restart Claude Desktop — the MCP tools will appear automatically.

## Available MCP Tools

| Tool | Description |
|------|-------------|
| `analyze_file_triage(file_path)` | Hashes (MD5/SHA1/SHA256/ssdeep), MIME type, entropy, imphash, and DIE scan |
| `extract_pe_info(file_path)` | Deep PE structure analysis: imphash, sections, entropy anomalies, DLL/EXE flags |
| `scan_yara(file_path)` | Scan with all YARA rules from the `/rules` directory |
| `get_strings(file_path, min_length)` | Extract ASCII/Unicode strings and filter IOC candidates (IPs, URLs, emails, paths) |
| `check_virustotal(file_hash)` | Look up a file hash on VirusTotal (requires API key) |

## Security Features

- All file analysis runs inside an isolated Docker container with:
  - Read-only filesystem (`read_only: true`)
  - No new privileges (`no-new-privileges:true`)
  - All Linux capabilities dropped (`cap_drop: ALL`)
  - Memory limit: 2 GB
  - CPU limit: 2 cores
- Samples and rules are mounted **read-only**
- Directory traversal protection in the worker API

## Project Structure

```
jumal-mcp/
├── Dockerfile                  # Worker container image
├── docker-compose.yml          # Container orchestration
├── requirements.txt            # Worker Python dependencies
├── bridge/
│   ├── bridge.py               # MCP Bridge (runs on host, stdio)
│   └── claude_desktop_config.json  # Example Claude Desktop config
└── worker/
    └── main.py                 # FastAPI analysis worker
```

## License

MIT
