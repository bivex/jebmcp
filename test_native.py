import json
import http.client

jsonrpc_request_id = 1

def make_jsonrpc_request(method: str, *params):
    """Make a JSON-RPC request to the JEB plugin"""
    global jsonrpc_request_id
    conn = http.client.HTTPConnection("localhost", 16161)
    request = {
        "jsonrpc": "2.0",
        "method": method,
        "params": list(params),
        "id": jsonrpc_request_id,
    }
    jsonrpc_request_id += 1

    try:
        conn.request("POST", "/mcp", json.dumps(request), {
            "Content-Type": "application/json"
        })
        response = conn.getresponse()
        data = json.loads(response.read().decode())

        if "error" in data:
            error = data["error"]
            code = error["code"]
            message = error["message"]
            pretty = f"JSON-RPC error {code}: {message}"
            if "data" in error:
                pretty += "\n" + error["data"]
            raise Exception(pretty)

        result = data.get("result")
        # NOTE: LLMs do not respond well to empty responses
        if result is None:
            result = "success"
        return result
    finally:
        conn.close()

def main():
    # User-provided data
    filepath = "C:\\Users\\Admin\\Desktop\\Dev\\jebmcp\\app-debug.apk"
    lib_name = "libnative-lib.so"

    print("Testing native analysis functions...")
    print(f"Filepath: {filepath}")
    print(f"Library: {lib_name}")

    try:
        # Check connection
        print("\n--- Checking connection ---")
        try:
            conn = http.client.HTTPConnection("localhost", 16161, timeout=5)
            conn.connect()
            conn.close()
            print("Successfully connected to JEB Pro plugin server.")
        except Exception as e:
            print(f"Failed to connect to JEB Pro plugin server: {e}")
            print("Please ensure JEB is running and the MCP script is active (Edit -> Scripts -> MCP).")
            return

        # 1. Get native libraries
        print("\n--- Getting native libraries ---")
        libs = make_jsonrpc_request('get_native_libraries', filepath)
        print("Received libraries:", json.dumps(libs, indent=2))
        if not libs:
            print("Warning: get_native_libraries returned an empty list.")

        # 2. Load native library
        print(f"\n--- Loading native library: {lib_name} ---")
        lib_info = make_jsonrpc_request('load_native_library', filepath, lib_name)
        print(json.dumps(lib_info, indent=2))

        # 3. Get native functions
        print(f"\n--- Getting functions for {lib_name} ---")
        functions = make_jsonrpc_request('get_native_functions', filepath, lib_name)
        if functions != "success":
            print(f"Found {len(functions)} functions.")
            # print first 5 for brevity
            print(json.dumps(functions[:5], indent=2))

            # 4. Decompile a native function (if any found)
            if functions:
                # Try to find a specific function for a stable test
                target_function = next((f for f in functions if 'Java_com_erev0s_jniapp_MainActivity_Jniint' in f.get('name', '')), None)
                
                # Fallback to the first function if specific one is not found
                if not target_function:
                    target_function = functions[0]

                func_addr = target_function['address']
                func_name = target_function.get('name', 'N/A')
                print(f"\n--- Decompiling function: {func_name} at {func_addr} ---")
                decompiled_code = make_jsonrpc_request('decompile_native_function', filepath, lib_name, func_addr)
                print(decompiled_code)

                # 5. Find xrefs to this function
                print(f"\n--- Finding cross-references to {func_name} at {func_addr} ---")
                xrefs = make_jsonrpc_request('find_native_xrefs', filepath, lib_name, func_addr)
                print(json.dumps(xrefs, indent=2))

        # 6. Get native strings
        print(f"\n--- Getting strings from {lib_name} ---")
        strings = make_jsonrpc_request('get_native_strings', filepath, lib_name)
        if strings != "success":
            print(f"Found {len(strings)} strings.")
            print("First 10 strings:")
            for s in strings[:10]:
                print(s.get('value'))

        # 7. Get native imports
        print(f"\n--- Getting imports for {lib_name} ---")
        imports = make_jsonrpc_request('get_native_imports', filepath, lib_name)
        print(json.dumps(imports, indent=2))

        # 8. Get native exports
        print(f"\n--- Getting exports for {lib_name} ---")
        exports = make_jsonrpc_request('get_native_exports', filepath, lib_name)
        print(json.dumps(exports, indent=2))

    except Exception as e:
        print(f"\nAn error occurred: {e}")

if __name__ == "__main__":
    main() 
