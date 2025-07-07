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
   - `File -> Scripts -> Registered`
   - Select `MCP.py` from the list and click "Run"
   - You should see the following messages:
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

5. **Configure your AI assistant** using the configuration from `sample_cline_mcp_settings.json`

6. **Restart the MCP server in Cursor:** `Ctrl+Shift+P` → "MCP: Restart Server"

✅ Done! Now the AI can analyze APK files via JEB Pro.

## Requirements

- **JEB Pro** - an installed and licensed version of JEB Pro (tested on version 5.30.0)
- **Python 3.7+** - for the MCP server to run
- **uv** - recommended Python package manager (optional)

## Compatibility

✅ **JEB Pro 5.30.0** - fully supported
✅ **JEB Pro 5.x** - compatible
⚠️ **JEB Pro 4.x** - may require script adjustments

## Installation and Setup

### 1. Clone the repository

```bash
git clone <repository-url>
cd jebmcp
```

### 2. Install dependencies

Using pip:
```bash
cd jeb-mcp
pip install -e .
```

Or using uv (recommended):
```bash
cd jeb-mcp
uv install
```

### 3. Configure JEB Pro

You need to run the `MCP.py` script in JEB Pro. The file is located at:
```
jeb-mcp/src/jeb_mcp/MCP.py
```

**Recommended:** Copy the `MCP.py` file to the `scripts\samples` folder inside your JEB Pro directory for easy access:
```
[JEB_PRO_DIR]\scripts\samples\MCP.py
```

### 4. Running the script in JEB Pro

**Method 1: Via registered scripts (recommended)**
1. Copy `MCP.py` to the `[JEB_PRO_DIR]\scripts\samples\` folder
2. Open JEB Pro
3. Go to `File -> Scripts -> Registered`
4. Select `MCP.py` from the list of registered scripts
5. Click "Run"

**Method 2: Via the File menu**
1. Open JEB Pro
2. Go to `File -> Scripts -> Run Script...`
3. Select the `MCP.py` file from the `jeb-mcp/src/jeb_mcp/` folder
4. Click "Open" or "Run"

**Method 3: Via the Scripts menu**
1. Go to `Scripts -> Run Script...`
2. Select the `MCP.py` file

**Method 4: Drag and drop the file (easiest method)**
- Simply drag the `MCP.py` file into the JEB Pro window
- A dialog box should appear to run the script

**Method 5: Via the script console**
1. Open the console: `View -> Console` or `Scripts -> Console`
2. Enter the command:
```python
exec(open('C:/path/to/jeb-mcp/src/jeb_mcp/MCP.py').read())
```

**Method 6: Hotkeys (if configured)**
- `Ctrl+Shift+P` - open the command palette
- Find "Run Script" and select the file

### 5. Verify the launch

After running the script, you should see these messages in the JEB Pro console:
```
[I] Initializing Jython, please wait...
[MCP] Plugin loaded
[MCP] Plugin running
[MCP] Server started at http://localhost:16161
```

**Where to find messages in JEB Pro 5.30:**
- Open the console: `View -> Console` or click the console icon at the bottom
- Check the "Output" tab - the plugin messages will appear there
- Possibly also in the "Scripts" tab

**⚠️ IMPORTANT:** The script must remain running! Do not close the script execution window.

**How to check if the server is running:**
- The HTTP server should be running on `localhost:16161`
- The message `[MCP] Server started at http://localhost:16161` confirms a successful launch
- You can check in your browser: `http://localhost:16161/mcp` (should return a JSON-RPC error)
- Or use `netstat -an | findstr 16161` in the command line

### 6. Potential issues when running the script

**❌ Script does not run:**
- Check the JEB Pro console for errors
- Make sure port 16161 is free
- Check the path to `MCP.py`

**❌ No Scripts menu items:**
- In some versions of JEB Pro, the menu may be different
- Try `File -> Run Script` or `Tools -> Scripts`
- Use drag and drop

**❌ Script terminates immediately:**
- Check for syntax errors
- Make sure you are using the correct version of Python in JEB Pro

**❌ Module import error:**
- The script is written for Python 2.7 (compatible with JEB Pro)
- All necessary modules are already included

### 7. Start the MCP server

After the script is running in JEB Pro, start the MCP server:

```bash
cd jeb-mcp/src/jeb_mcp
python server.py
```

Or with uv:
```bash
uv --directory jeb-mcp/src/jeb_mcp run server.py
```

### 8. Configure your AI assistant (e.g., Cline)

Use the configuration from the `sample_cline_mcp_settings.json` file:

```json
{
    "mcpServers": {
      "jeb": {
        "command": "cmd",
        "args": [
          "/c",
          "uv",
          "--directory",
          "path\\to\\project\\jeb-mcp\\src\\jeb_mcp",
          "run",
          "server.py"
        ],
        "timeout": 1800,
        "disabled": false,
        "autoApprove": [
          "get_manifest",
          "get_method_callers",
          "get_class_decompiled_code",
          "get_method_decompiled_code",
          "check_connection",
          "ping",
          "get_method_overrides"
        ]
      }
    }
}
```

### 9. Restart the server in Cursor and analyze the APK

After configuring the MCP server:

1. **Restart the MCP server in Cursor:**
   - Open the command palette: `Ctrl+Shift+P`
   - Find "MCP: Restart Server"
   - Or restart Cursor completely

2. **Check the connection:**
   - In the AI chat, enter a command to check the connection
   - A message about a successful connection to JEB Pro should appear

3. **Start analysis:**
   - Load the APK file into JEB Pro
   - Ask the AI to analyze the file via MCP tools
   - Use full paths to APK files

**Example commands for the AI:**
```
Check connection with JEB Pro
Get manifest from file C:\path\to\app.apk
Decompile class Lcom/example/MainActivity; from file C:\path\to\app.apk
Find calls to method Lcom/example/Utils;->encrypt(Ljava/lang/String;)Ljava/lang/String;
```

## 🎯 What to do after a successful launch

If you see these messages:
```
[I] Initializing Jython, please wait...
[MCP] Plugin loaded
[MCP] Plugin running
[MCP] Server started at http://localhost:16161
```

**Congratulations! The system is working. Now you can:**

1. **Load an APK file into JEB Pro** for analysis
2. **Restart the MCP server in Cursor** (`Ctrl+Shift+P` → "MCP: Restart Server")
3. **Check the connection** via the AI assistant
4. **Start analyzing** - ask the AI to analyze the APK file

**Important points:**
- ✅ The script must remain running in JEB Pro
- ✅ APK files must be loaded in JEB Pro before analysis
- ✅ Use full file paths in commands
- ✅ The first launch may take time (Jython initialization)

## Available Functions

After launching, the MCP server provides the following tools:

### 1. `ping()`
Checks the connection with JEB Pro
```python
# Example usage
result = ping()
```

### 2. `check_connection()`
Checks if the plugin is running in JEB Pro
```python
status = check_connection()
```

### 3. `get_manifest(filepath)`
Gets the manifest of an APK file
```python
manifest = get_manifest("/path/to/app.apk")
```

### 4. `get_method_decompiled_code(filepath, method_signature)`
Decompiles a specific method
```python
code = get_method_decompiled_code(
    "/path/to/app.apk",
    "Lcom/example/MyClass;->myMethod(Ljava/lang/String;)V"
)
```

### 5. `get_class_decompiled_code(filepath, class_signature)`
Decompiles an entire class
```python
code = get_class_decompiled_code(
    "/path/to/app.apk",
    "Lcom/example/MyClass;"
)
```

### 6. `get_method_callers(filepath, method_signature)`
Finds where a method is called
```python
callers = get_method_callers(
    "/path/to/app.apk",
    "Lcom/example/MyClass;->myMethod(Ljava/lang/String;)V"
)
```

### 7. `get_method_overrides(filepath, method_signature)`
Finds method overrides
```python
overrides = get_method_overrides(
    "/path/to/app.apk",
    "Lcom/example/MyClass;->myMethod(Ljava/lang/String;)V"
)
```

## Signature Format

Java-style internal addresses are used for working with methods and classes:

- **Package**: `Lcom/example/`
- **Class**: `Lcom/example/MyClass;`
- **Method**: `Lcom/example/MyClass;->myMethod(Ljava/lang/String;)V`
- **Field**: `Lcom/example/MyClass;->myField:I`

## Usage Examples

### Analyzing an APK file
```python
# Check connection
connection_status = check_connection()
print(connection_status)

# Get manifest
manifest = get_manifest("/path/to/app.apk")
print(manifest)

# Decompile a class
class_code = get_class_decompiled_code(
    "/path/to/app.apk",
    "Lcom/example/MainActivity;"
)
print(class_code)
```

### Finding method calls
```python
# Find who calls the method
callers = get_method_callers(
    "/path/to/app.apk",
    "Lcom/example/Utils;->encrypt(Ljava/lang/String;)Ljava/lang/String;"
)

for caller_class, caller_method in callers:
    print(f"Called from: {caller_class} -> {caller_method}")
```

## Troubleshooting

### Problems running the script in JEB Pro
1. **Script not found in the menu (JEB Pro 5.30):**
   - Use `File -> Scripts -> Run Script...`
   - Try dragging and dropping the `MCP.py` file into the JEB Pro window (recommended)
   - Check the file extension (.py)
   - In some versions, the path might be `Scripts -> Run Script...`

2. **Script terminates with an error:**
   - Open the JEB Pro console: `View -> Console` or `Scripts -> Console`
   - Check the "Scripts" tab in the bottom panel for errors
   - Make sure you are using the original `MCP.py` file
   - Check that port 16161 is not occupied by another process

3. **"Plugin loaded" messages do not appear:**
   - Restart JEB Pro
   - Check the output console: `View -> Console` -> "Output" tab
   - Try running the script from the console:
     ```python
     exec(open('path/to/MCP.py').read())
     ```

4. **JEB Pro 5.30 specifics:**
   - The console is located in `View -> Console` or at the bottom of the window
   - Scripts run in separate tabs
   - Logs may appear in different console tabs
   - Use the "Scripts" tab to view script execution

### MCP server connection errors
1. **"Failed to connect to JEB Pro":**
   - Make sure JEB Pro is running
   - Check that the MCP.py script is running (you should see `[MCP] Plugin running` messages)
   - Make sure port 16161 is free
   - Use `check_connection()` to verify the setup

2. **"Connection refused":**
   - Restart the script in JEB Pro
   - Check your firewall and antivirus
   - Make sure localhost is accessible

### Decompilation errors
1. **"Method not found" or "Class not found":**
   - Check the correctness of method/class signatures
   - Use the exact format: `Lcom/example/Class;->method(Ljava/lang/String;)V`
   - Make sure the APK file is loaded in JEB Pro

2. **"File not found":**
   - Make sure you are using full absolute paths to files
   - Check that the APK file exists and is accessible

### Dependency issues
```bash
# Reinstall dependencies
pip install --upgrade fastmcp

# Or with uv
uv sync
```

### Python environment issues
```bash
# Check Python version
python --version

# Make sure fastmcp is installed
pip show fastmcp
```

## Logs and Debugging

The MCP server starts with the ERROR logging level for compatibility with Cline. For debugging, you can change the level in the `server.py` file:

```python
mcp = FastMCP("github.com/flankerhqd/jeb-pro-mcp", log_level="DEBUG")
```

## Support

This project is based on the [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) architecture.

**Tested on:**
- JEB Pro 5.30.0.202506111623
- Windows 10/11
- Python 3.7+

If you encounter problems:
1. Check that all components are running
2. Ensure the paths and signatures are correct
3. Use the `ping()` function to check the connection
4. For JEB Pro 5.30 - check the console in `View -> Console`

## License

This project uses an architecture licensed under the MIT license from [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp).
