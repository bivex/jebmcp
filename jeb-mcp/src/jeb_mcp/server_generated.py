# NOTE: This file has been automatically generated, do not modify!
# Architecture based on https://github.com/mrexodia/ida-pro-mcp (MIT License)
from typing import Annotated, Optional, TypedDict, Generic, TypeVar, List, Tuple
from pydantic import Field

T = TypeVar("T")

@mcp.tool()
def manifest(filepath: str) -> str:
    """Get the AndroidManifest.xml content of an APK file"""
    return make_jsonrpc_request('get_manifest', filepath)

@mcp.tool()
def decompile_method(filepath: str, method_signature: str) -> str:
    """Decompile specific method to Java code
    
    Dex units use Java-style internal addresses to identify items:
    - package: Lcom/abc/
    - type: Lcom/abc/Foo;
    - method: Lcom/abc/Foo;->bar(I[JLjava/Lang/String;)V
    - field: Lcom/abc/Foo;->flag1:Z

    Args:
        filepath: Absolute path to the APK file
        method_signature: Fully-qualified method signature, e.g. Lcom/abc/Foo;->bar(I[JLjava/Lang/String;)V
    """
    return make_jsonrpc_request('get_method_decompiled_code', filepath, method_signature)

@mcp.tool()
def decompile_class(filepath: str, class_signature: str) -> str:
    """Decompile entire class to Java code
    
    Dex units use Java-style internal addresses to identify items:
    - package: Lcom/abc/
    - type: Lcom/abc/Foo;
    - method: Lcom/abc/Foo;->bar(I[JLjava/Lang/String;)V
    - field: Lcom/abc/Foo;->flag1:Z

    Args:
        filepath: Absolute path to the APK file
        class_signature: Fully-qualified signature of the class, e.g. Lcom/abc/Foo;
    """
    return make_jsonrpc_request('get_class_decompiled_code', filepath, class_signature)

@mcp.tool()
def find_callers(filepath: str, method_signature: str) -> List[Tuple[str,str]]:
    """Find all methods calling this method (cross-references)
    
    Args:
        filepath: Absolute path to the APK file
        method_signature: Fully-qualified method signature
        
    Returns:
        List of tuples (address, details) for each caller
    """
    return make_jsonrpc_request('get_method_callers', filepath, method_signature)

@mcp.tool()
def find_overrides(filepath: str, method_signature: str) -> List[Tuple[str,str]]:
    """Find all methods overriding this method
    
    Args:
        filepath: Absolute path to the APK file
        method_signature: Fully-qualified method signature
        
    Returns:
        List of tuples (address, details) for each override
    """
    return make_jsonrpc_request('get_method_overrides', filepath, method_signature)

@mcp.tool()
def native_libraries(filepath: str) -> list:
    """Get list of native libraries (.so files) in APK
    
    Args:
        filepath: Absolute path to the APK file
        
    Returns:
        List of native libraries with name, type, and architecture
    """
    return make_jsonrpc_request('get_native_libraries', filepath)

@mcp.tool()
def load_native_lib(filepath: str, lib_name: str) -> dict:
    """Load and get info about specific native library
    
    Args:
        filepath: Absolute path to the APK file
        lib_name: Name of the native library (e.g., "libnative.so")
        
    Returns:
        Library info including architecture, entry point, base address
    """
    return make_jsonrpc_request('load_native_library', filepath, lib_name)

@mcp.tool()
def native_functions(filepath: str, lib_name: str) -> list:
    """Get list of exported functions in a native library.
    
    Args:
        filepath: Absolute path to the APK file
        lib_name: Name of the native library
        
    Returns:
        List of functions with their addresses and names.
    """
    return make_jsonrpc_request('get_native_functions', filepath, lib_name)

@mcp.tool()
def decompile_native(filepath: str, lib_name: str, function_address: str) -> str:
    """Decompile native function to C-like pseudocode
    
    Args:
        filepath: Absolute path to the APK file
        lib_name: Name of the native library
        function_address: Address of the function (hex format)
        
    Returns:
        Decompiled C-like pseudocode
    """
    return make_jsonrpc_request('decompile_native', filepath, lib_name, function_address)

@mcp.tool()
def native_strings(filepath: str, lib_name: str) -> list:
    """Get all printable strings from a native library.
    
    Args:
        filepath: Absolute path to the APK file
        lib_name: Name of the native library
        
    Returns:
        A list of strings found in the library's string table sections.
    """
    return make_jsonrpc_request('get_native_strings', filepath, lib_name)

@mcp.tool()
def native_xrefs(filepath: str, lib_name: str, address: str) -> list:
    """Find cross-references to/from native address
    
    Args:
        filepath: Absolute path to the APK file
        lib_name: Name of the native library
        address: Memory address (hex format)
        
    Returns:
        List of cross-references with addresses and details
    """
    return make_jsonrpc_request('find_native_xrefs', filepath, lib_name, address)

@mcp.tool()
def native_imports(filepath: str, lib_name: str) -> list:
    """Get imported functions/libraries for native library
    
    Args:
        filepath: Absolute path to the APK file
        lib_name: Name of the native library
        
    Returns:
        List of imported functions with names, libraries, and addresses
    """
    return make_jsonrpc_request('get_native_imports', filepath, lib_name)

@mcp.tool()
def native_exports(filepath: str, lib_name: str) -> list:
    """Get exported functions from native library
    
    Args:
        filepath: Absolute path to the APK file
        lib_name: Name of the native library
        
    Returns:
        List of exported functions with names, addresses, and ordinals
    """
    return make_jsonrpc_request('get_native_exports', filepath, lib_name)

@mcp.tool()
def is_native_unit_processed(filepath: str, lib_name: str) -> bool:
    """Check if the analysis of a native code unit is complete.
    
    Args:
        filepath: Absolute path to the APK file
        lib_name: Name of the native library
        
    Returns:
        True if analysis is complete, False otherwise.
    """
    return make_jsonrpc_request('is_native_unit_processed', filepath, lib_name)

@mcp.tool()
def process_native_unit(filepath: str, lib_name: str) -> bool:
    """Explicitly starts the analysis of a native code unit.
    
    This is equivalent to double-clicking the unit in the UI.
    
    Args:
        filepath: Absolute path to the APK file
        lib_name: Name of the native library
        
    Returns:
        True if processing was started, False otherwise.
    """
    return make_jsonrpc_request('process_native_unit', filepath, lib_name)
