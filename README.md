# JEB Pro MCP Server

An MCP (Model Context Protocol) server for integration with the JEB Pro reverse-engineering tool. It allows AI assistants to interact with JEB Pro to analyze Android APK files.

![jebmcp](https://github.com/user-attachments/assets/28ea1c0e-76a7-4ed2-84b6-17645f671156)

## What is this?

This project is a bridge between AI assistants (like Cline) and JEB Pro, a professional tool for analyzing and decompiling mobile applications. It enables AI to automate the process of analyzing APK files.

## 🚀 Quick Start

1. **Install dependencies:**
   ```bash
   cd jeb-mcp && pip install -e .
   ```

2. **Copy the script to JEB Pro:**
   ```bash
   copy jeb-mcp\src\jeb_mcp\MCP.py [JEB_PRO_DIR]\scripts\samples\
   ```

3. **Run the script in JEB Pro:**
   - Open JEB Pro
   - `File -> Scripts -> Registered` (or drag `MCP.py` into JEB Pro window)
   - Select `MCP.py` and click "Run"
   - Verify these messages appear in console (`View -> Console`):
     ```
     [I] Initializing Jython, please wait...
     [MCP] Plugin loaded
     [MCP] Plugin running
     [MCP] Server started at http://localhost:16161
     ```

4. **Start the MCP server:**
   ```bash
   cd jeb-mcp/src/jeb_mcp && python server.py
   ```

5. **Configure your AI assistant** using `sample_cline_mcp_settings.json`

6. **Restart MCP server in Cursor:** `Ctrl+Shift+P` → "MCP: Restart Server"

✅ Done! Now AI can analyze APK files via JEB Pro.

## Requirements

- **JEB Pro** - installed and licensed (tested on version 5.30.0)
- **Python 3.7+** - for the MCP server
- **uv** - recommended Python package manager (optional)

## Compatibility

✅ **JEB Pro 5.30.0** - fully supported  
✅ **JEB Pro 5.x** - compatible  
⚠️ **JEB Pro 4.x** - may require script adjustments

## Installation and Setup

### 1. Clone and Install

```bash
git clone <repository-url>
cd jebmcp/jeb-mcp
pip install -e .
# Or with uv: uv install
```

### 2. Run Script in JEB Pro

Copy `MCP.py` to JEB Pro's scripts folder:
```
[JEB_PRO_DIR]\scripts\samples\MCP.py
```

**Methods to run the script:**
- **Recommended:** Drag `MCP.py` file into JEB Pro window
- `File -> Scripts -> Registered` → Select `MCP.py` → Run
- `File -> Scripts -> Run Script...` → Browse to `MCP.py`

**⚠️ IMPORTANT:** Keep the script running! Don't close the execution window.

### 3. Verify Launch

Check JEB Pro console (`View -> Console`, "Output" tab) for:
```
[I] Initializing Jython, please wait...
[MCP] Plugin loaded
[MCP] Plugin running
[MCP] Server started at http://localhost:16161
```

### 4. Start MCP Server

```bash
cd jeb-mcp/src/jeb_mcp
python server.py
# Or: uv --directory jeb-mcp/src/jeb_mcp run server.py
```

### 5. Configure AI Assistant

Use configuration from `sample_cline_mcp_settings.json`:

```json
{
    "mcpServers": {
      "jeb": {
        "command": "cmd",
        "args": ["/c", "uv", "--directory", "path\\to\\jeb-mcp\\src\\jeb_mcp", "run", "server.py"],
        "timeout": 1800,
        "disabled": false,
        "autoApprove": ["get_manifest", "get_method_callers", "get_class_decompiled_code", "get_method_decompiled_code", "check_connection", "ping", "get_method_overrides"]
      }
    }
}
```

### 6. Start Analysis

1. **Restart MCP server in Cursor:** `Ctrl+Shift+P` → "MCP: Restart Server"
2. **Load APK in JEB Pro** before analysis
3. **Test connection** through AI assistant
4. **Begin analysis** using full file paths

## Available Functions

### Connection Functions
- `ping()` - Check connection with JEB Pro
- `check_connection()` - Verify plugin is running

### Analysis Functions
- `get_manifest(filepath)` - Get APK manifest
- `get_class_decompiled_code(filepath, class_signature)` - Decompile entire class
- `get_method_decompiled_code(filepath, method_signature)` - Decompile specific method
- `get_method_callers(filepath, method_signature)` - Find method call locations
- `get_method_overrides(filepath, method_signature)` - Find method overrides

## Signature Format

Use Java-style internal addresses:
- **Package**: `Lcom/example/`
- **Class**: `Lcom/example/MyClass;`
- **Method**: `Lcom/example/MyClass;->myMethod(Ljava/lang/String;)V`
- **Field**: `Lcom/example/MyClass;->myField:I`

## Usage Examples

```python
# Check connection
status = check_connection()

# Get manifest
manifest = get_manifest("/path/to/app.apk")

# Decompile class
code = get_class_decompiled_code("/path/to/app.apk", "Lcom/example/MainActivity;")

# Find method callers
callers = get_method_callers("/path/to/app.apk", "Lcom/example/Utils;->encrypt(Ljava/lang/String;)Ljava/lang/String;")
```

## Troubleshooting

### Script Issues
- **Script not found:** Use drag-and-drop or `File -> Scripts -> Run Script...`
- **Script terminates:** Check JEB Pro console for errors, ensure port 16161 is free
- **No output:** Check `View -> Console` → "Output" tab

### Connection Issues
- **Connection failed:** Ensure JEB Pro and script are running, port 16161 is free
- **Plugin not found:** Restart script in JEB Pro, verify console messages

### Analysis Issues
- **Method/Class not found:** Check signature format, ensure APK is loaded in JEB Pro
- **File not found:** Use full absolute paths

### Dependencies
```bash
pip install --upgrade fastmcp  # Or: uv sync
```

## Debugging

Change log level in `server.py` for debugging:
```python
mcp = FastMCP("github.com/flankerhqd/jeb-pro-mcp", log_level="DEBUG")
```

## Support

Based on [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) architecture.

**Tested on:**
- JEB Pro 5.30.0.202506111623
- Windows 10/11
- Python 3.7+

## License

MIT license from [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp).
