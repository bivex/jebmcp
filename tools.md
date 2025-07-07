# JEB Pro MCP Tools Documentation

This document provides a comprehensive overview of all available MCP (Model Context Protocol) tools in the JEB Pro MCP Server.

## Overview

The JEB Pro MCP Server provides tools for analyzing Android APK files through JEB Pro's reverse engineering capabilities. The server operates through JSON-RPC communication with the JEB Pro plugin running at `localhost:16161`.

## Available Tools

| Tool Name | Parameters | Return Type | Description | Example Usage |
|-----------|------------|-------------|-------------|---------------|
| `manifest` | `filepath: str` | `str` | Get AndroidManifest.xml content | `manifest("/path/to/app.apk")` |
| `decompile_method` | `filepath: str`<br>`method_signature: str` | `str` | Decompile specific method to Java code | `decompile_method("/path/to/app.apk", "Lcom/example/MainActivity;->onCreate(Landroid/os/Bundle;)V")` |
| `decompile_class` | `filepath: str`<br>`class_signature: str` | `str` | Decompile entire class to Java code | `decompile_class("/path/to/app.apk", "Lcom/example/MainActivity;")` |
| `find_callers` | `filepath: str`<br>`method_signature: str` | `list[(str,str)]` | Find all methods calling this method | `find_callers("/path/to/app.apk", "Lcom/example/Utils;->encrypt(Ljava/lang/String;)Ljava/lang/String;")` |
| `find_overrides` | `filepath: str`<br>`method_signature: str` | `list[(str,str)]` | Find all methods overriding this method | `find_overrides("/path/to/app.apk", "Ljava/lang/Object;->toString()Ljava/lang/String;")` |

## Native Code Analysis Tools (.so libraries / JNI)

| Tool Name | Parameters | Return Type | Description | Example Usage |
|-----------|------------|-------------|-------------|---------------|
| `native_libraries` | `filepath: str` | `list` | Get list of native libraries in APK | `native_libraries("/path/to/app.apk")` |
| `load_native_lib` | `filepath: str`<br>`lib_name: str` | `dict` | Load and get info about native library | `load_native_lib("/path/to/app.apk", "libnative.so")` |
| `native_functions` | `filepath: str`<br>`lib_name: str` | `list` | Get list of exported functions in a native library. | `native_functions("/path/to/app.apk", "libnative.so")` |
| `decompile_native` | `filepath: str`<br>`lib_name: str`<br>`function_address: str` | `str` | Decompile native function to C pseudocode | `decompile_native("/path/to/app.apk", "libnative.so", "0x1000")` |
| `native_strings` | `filepath: str`<br>`lib_name: str` | `list` | Get all printable strings from a native library. | `native_strings("/path/to/app.apk", "libnative.so")` |
| `native_xrefs` | `filepath: str`<br>`lib_name: str`<br>`address: str` | `list` | Find cross-references to/from native address | `native_xrefs("/path/to/app.apk", "libnative.so", "0x1000")` |
| `native_imports` | `filepath: str`<br>`lib_name: str` | `list` | Get imported functions/libraries | `native_imports("/path/to/app.apk", "libnative.so")` |
| `native_exports` | `filepath: str`<br>`lib_name: str` | `list` | Get exported functions from library | `native_exports("/path/to/app.apk", "libnative.so")` |

## Parameter Details

### File Path Requirements
- **filepath**: Must be an absolute path to the APK file
- The APK file must be accessible to the JEB Pro instance
- Multiple APK files can be analyzed simultaneously (up to 10 loaded artifacts)

### Signature Formats
JEB Pro uses Java-style internal addresses to identify items:

| Item Type | Format | Example |
|-----------|--------|---------|
| Package | `Lcom/abc/` | `Lcom/example/myapp/` |
| Class/Type | `Lcom/abc/Foo;` | `Lcom/example/MainActivity;` |
| Method | `Lcom/abc/Foo;->methodName(parameters)returnType` | `Lcom/example/MainActivity;->onCreate(Landroid/os/Bundle;)V` |
| Field | `Lcom/abc/Foo;->fieldName:Type` | `Lcom/example/MainActivity;->isDebug:Z` |

### Common Java Type Signatures
| Java Type | Signature | Description |
|-----------|-----------|-------------|
| `void` | `V` | Void return type |
| `boolean` | `Z` | Boolean primitive |
| `int` | `I` | Integer primitive |
| `long` | `J` | Long primitive |
| `String` | `Ljava/lang/String;` | String object |
| `Bundle` | `Landroid/os/Bundle;` | Android Bundle |
| `int[]` | `[I` | Integer array |
| `String[]` | `[Ljava/lang/String;` | String array |

## Return Value Details

### String Returns
- `manifest`: Returns the full AndroidManifest.xml content as text
- `decompile_method`: Returns decompiled Java source code for method
- `decompile_class`: Returns decompiled Java source code for entire class

### List Returns
- `find_callers`: Returns list of tuples `(address, details)` where:
  - `address`: Memory address or method signature of the caller
  - `details`: Additional information about the calling context
- `find_overrides`: Returns list of tuples `(address, details)` for override relationships

## Error Handling

The server handles various error conditions:

- **Connection Errors**: If JEB Pro plugin is not running, connection tools will provide instructions
- **File Not Found**: Invalid file paths will raise exceptions
- **Invalid Signatures**: Malformed method/class signatures will return appropriate error messages
- **Analysis Errors**: Issues during decompilation will be reported with context

## Setup Requirements

1. **JEB Pro**: Must be running with the MCP plugin loaded
2. **Plugin Activation**: Run `Edit -> Scripts -> MCP` in JEB Pro (shortcut: `Ctrl+Alt+M` on Windows/Linux, `Ctrl+Option+M` on macOS)
3. **Network**: Server runs on `localhost:16161`
4. **File Access**: APK files must be accessible from the JEB Pro process

## Usage Examples

### Basic Workflow
```python
# 1. Analyze manifest
app_manifest = manifest("/path/to/app.apk")

# 2. Get class structure
main_activity = decompile_class("/path/to/app.apk", "Lcom/example/MainActivity;")

# 3. Analyze specific method
onCreate_code = decompile_method("/path/to/app.apk", "Lcom/example/MainActivity;->onCreate(Landroid/os/Bundle;)V")

# 4. Find callers
callers = find_callers("/path/to/app.apk", "Lcom/example/Utils;->sensitiveMethod()V")
```

### Native Code Analysis
```
