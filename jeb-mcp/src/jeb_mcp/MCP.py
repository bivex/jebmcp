# -*- coding: utf-8 -*-
import sys

from com.pnfsoftware.jeb.client.api import IScript
from com.pnfsoftware.jeb.core.units import INativeCodeUnit
from com.pnfsoftware.jeb.core.units.code.android import IDexUnit
from com.pnfsoftware.jeb.core.util import DecompilerHelper

from com.pnfsoftware.jeb.client.api import IScript, IconType, ButtonGroupType
from com.pnfsoftware.jeb.core import JebCoreService, ICoreContext, Artifact, RuntimeProjectUtil

from com.pnfsoftware.jeb.core.input import FileInput
from com.pnfsoftware.jeb.core.units import INativeCodeUnit
from com.pnfsoftware.jeb.core.units.code.android import IDexUnit
from com.pnfsoftware.jeb.core.units.code import ICodeUnit
from com.pnfsoftware.jeb.core.output.text import ITextDocument
from com.pnfsoftware.jeb.core.util import DecompilerHelper
from com.pnfsoftware.jeb.core.units.code.android import IApkUnit
from com.pnfsoftware.jeb.core.output.text import TextDocumentUtil
from com.pnfsoftware.jeb.core.units.code.asm.decompiler import INativeSourceUnit
from com.pnfsoftware.jeb.core.actions import ActionContext, Actions, ActionXrefsData, ActionOverridesData
from java.io import File

import json
import struct
import threading
import traceback
import os
import time
# Python 2.7 changes - use urlparse from urlparse module instead of urllib.parse
from urlparse import urlparse
# Python 2.7 doesn't have typing, so we'll define our own minimal substitutes
# and ignore most type annotations

# Mock typing classes/functions for type annotation compatibility
class Any(object): pass
class Callable(object): pass
def get_type_hints(func):
    """Mock for get_type_hints that works with Python 2.7 functions"""
    hints = {}
    
    # Try to get annotations (modern Python way)
    if hasattr(func, '__annotations__'):
        hints.update(getattr(func, '__annotations__', {}))
    
    # For Python 2.7, inspect the function signature
    import inspect
    args, varargs, keywords, defaults = inspect.getargspec(func)
    
    # Add all positional parameters with Any type
    for arg in args:
        if arg not in hints:
            hints[arg] = Any
            
    return hints
class TypedDict(dict): pass
class Optional(object): pass
class Annotated(object): pass
class TypeVar(object): pass
class Generic(object): pass

# Use BaseHTTPServer instead of http.server
import BaseHTTPServer

class JSONRPCError(Exception):
    def __init__(self, code, message, data=None):
        Exception.__init__(self, message)
        self.code = code
        self.message = message
        self.data = data

class RPCRegistry(object):
    def __init__(self):
        self.methods = {}

    def register(self, func):
        self.methods[func.__name__] = func
        return func

    def dispatch(self, method, params):
        if method not in self.methods:
            raise JSONRPCError(-32601, "Method '{0}' not found".format(method))

        func = self.methods[method]
        hints = get_type_hints(func)

        # Remove return annotation if present
        if 'return' in hints:
            hints.pop("return", None)

        if isinstance(params, list):
            if len(params) != len(hints):
                raise JSONRPCError(-32602, "Invalid params: expected {0} arguments, got {1}".format(len(hints), len(params)))

            # Python 2.7 doesn't support zip with items() directly
            # Convert to simpler validation approach
            converted_params = []
            param_items = hints.items()
            for i, value in enumerate(params):
                if i < len(param_items):
                    param_name, expected_type = param_items[i]
                    # In Python 2.7, we'll do minimal type checking
                    converted_params.append(value)
                else:
                    converted_params.append(value)

            return func(*converted_params)
        elif isinstance(params, dict):
            # Simplify type validation for Python 2.7
            if set(params.keys()) != set(hints.keys()):
                raise JSONRPCError(-32602, "Invalid params: expected {0}".format(list(hints.keys())))

            # Validate and convert parameters
            converted_params = {}
            for param_name, expected_type in hints.items():
                value = params.get(param_name)
                # Skip detailed type validation in Python 2.7 version
                converted_params[param_name] = value

            return func(**converted_params)
        else:
            raise JSONRPCError(-32600, "Invalid Request: params must be array or object")

rpc_registry = RPCRegistry()

def jsonrpc(func):
    """Decorator to register a function as a JSON-RPC method"""
    global rpc_registry
    return rpc_registry.register(func)

class JSONRPCRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def send_jsonrpc_error(self, code, message, id=None):
        response = {
            "jsonrpc": "2.0",
            "error": {
                "code": code,
                "message": message
            }
        }
        if id is not None:
            response["id"] = id
        response_body = json.dumps(response)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(response_body))
        self.end_headers()
        self.wfile.write(response_body)

    def do_POST(self):
        global rpc_registry

        parsed_path = urlparse(self.path)
        if parsed_path.path != "/mcp":
            self.send_jsonrpc_error(-32098, "Invalid endpoint", None)
            return

        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            self.send_jsonrpc_error(-32700, "Parse error: missing request body", None)
            return

        request_body = self.rfile.read(content_length)
        try:
            request = json.loads(request_body)
        except ValueError:  # Python 2.7 uses ValueError instead of JSONDecodeError
            self.send_jsonrpc_error(-32700, "Parse error: invalid JSON", None)
            return

        # Prepare the response
        response = {
            "jsonrpc": "2.0"
        }
        if request.get("id") is not None:
            response["id"] = request.get("id")

        try:
            # Basic JSON-RPC validation
            if not isinstance(request, dict):
                raise JSONRPCError(-32600, "Invalid Request")
            if request.get("jsonrpc") != "2.0":
                raise JSONRPCError(-32600, "Invalid JSON-RPC version")
            if "method" not in request:
                raise JSONRPCError(-32600, "Method not specified")

            # Dispatch the method
            result = rpc_registry.dispatch(request["method"], request.get("params", []))
            response["result"] = result

        except JSONRPCError as e:
            response["error"] = {
                "code": e.code,
                "message": e.message
            }
            if e.data is not None:
                response["error"]["data"] = e.data
        except Exception as e:
            traceback.print_exc()
            response["error"] = {
                "code": -32603,
                "message": "Internal error (please report a bug)",
                "data": traceback.format_exc(),
            }

        try:
            response_body = json.dumps(response)
        except Exception as e:
            traceback.print_exc()
            response_body = json.dumps({
                "error": {
                    "code": -32603,
                    "message": "Internal error (please report a bug)",
                    "data": traceback.format_exc(),
                }
            })

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(response_body))
        self.end_headers()
        self.wfile.write(response_body)

    def log_message(self, format, *args):
        # Suppress logging
        pass

class MCPHTTPServer(BaseHTTPServer.HTTPServer):
    allow_reuse_address = False

class Server(object):  # Use explicit inheritance from object for py2
    HOST = "localhost"
    PORT = 16161

    def __init__(self):
        self.server = None
        self.server_thread = None
        self.running = False

    def start(self):
        if self.running:
            print("[MCP] Server is already running")
            return

        # Python 2.7 doesn't support daemon parameter in Thread constructor
        self.server_thread = threading.Thread(target=self._run_server)
        self.server_thread.daemon = True  # Set daemon attribute after creation
        self.running = True
        self.server_thread.start()

    def stop(self):
        if not self.running:
            return

        self.running = False
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.server_thread:
            self.server_thread.join()
            self.server = None
        print("[MCP] Server stopped")

    def _run_server(self):
        try:
            print("[MCP] Starting server on %s:%d" % (self.HOST, self.PORT))
            self.server = MCPHTTPServer((self.HOST, self.PORT), JSONRPCRequestHandler)
            self.server.serve_forever()
        except Exception as e:
            print("[MCP] Server error: %s" % str(e))
        finally:
            self.running = False
            print("[MCP] Server has stopped")

# A module that helps with writing thread safe ida code.
# Based on:
# https://web.archive.org/web/20160305190440/http://www.williballenthin.com/blog/2015/09/04/idapython-synchronization-decorator/
import logging
import Queue as queue  # Python 2.7 uses Queue instead of queue
import traceback
import functools

MAX_OPENED_ARTIFACTS = 5
artifactQueue = [] # Store up to MAX_OPENED_ARTIFACTS artifacts, then unload the oldest

def addArtifactToQueue(artifact):
    """Add an artifact to the queue, and remove the oldest if the queue is full"""
    global artifactQueue
    if len(artifactQueue) >= MAX_OPENED_ARTIFACTS:
        oldestArtifact = artifactQueue.pop(0)
        print('[MCP] Unloading artifact due to queue size: %s' % oldestArtifact.getName())
        try:
            # This is a bit aggressive, but necessary to free resources
            RuntimeProjectUtil.closeProject(oldestArtifact.getProject())
        except Exception as e:
            print('[MCP] Error unloading artifact: %s' % str(e))
            
    artifactQueue.append(artifact)

def getArtifactFromQueue():
    """Get the oldest artifact from the queue"""
    global artifactQueue
    if len(artifactQueue) > 0:
        return artifactQueue.pop(0)
    return None

def clearArtifactQueue():
    """Clear all artifacts from the queue"""
    global artifactQueue
    artifactQueue = []

def getOrLoadApk(filepath):
    """Get the APK unit from the current project or load it"""
    global CTX
    if not CTX:
        raise Exception("JEB context not available. Please try running the script again.")

    if not filepath or not os.path.exists(filepath):
        raise Exception("File not found: %s" % filepath)

    engctx = CTX.getEnginesContext()
    if not engctx:
        raise Exception('Back-end engines not initialized')

    # Use a dedicated project for our operations to not pollute the UI
    project = engctx.loadProject('MCPPluginProject')
    if not project:
        raise Exception('Failed to load MCP project')

    base_name = os.path.basename(filepath)
    
    # Check if artifact is already in our project
    for artifact in project.getLiveArtifacts():
        if artifact.getArtifact().getName() == base_name:
            print('[MCP] Found existing artifact: %s' % base_name)
            unit = artifact.getMainUnit()
            if isinstance(unit, IApkUnit):
                print('[MCP] Existing artifact found. Waiting for sub-units to be processed...')
                time.sleep(3) # Heuristic wait
                return unit

    # Artifact not found, let's process it
    print('[MCP] Processing new artifact: %s' % base_name)
    live_artifact = project.processArtifact(Artifact(base_name, FileInput(File(filepath))))
    if not live_artifact:
        raise Exception('Failed to process artifact')

    # Wait for the main unit to be available
    timeout = 60  # seconds
    start_time = time.time()
    unit = live_artifact.getMainUnit()
    while not unit and (time.time() - start_time) < timeout:
        time.sleep(1)
        unit = live_artifact.getMainUnit()

    if not unit:
        raise Exception('Timed out waiting for main unit to be available')
    
    print('[MCP] Main unit is available, waiting for analysis to complete...')
    time.sleep(3) # Heuristic wait for analysis to populate children units

    if isinstance(unit, IApkUnit):
        return unit
    
    raise Exception('Processed artifact is not an APK unit')

@jsonrpc
def get_manifest(filepath):
    """Get the AndroidManifest.xml content of an APK file"""
    if not filepath:
        return None

    apk = getOrLoadApk(filepath)  # Fixed: use getOrLoadApk function to load the APK
    #get base name
    
    if apk is None:
        # if the input is not apk (e.g. a jar or single dex, )
        # assume it runs in system context
        return None
    
    man = apk.getManifest()
    if man is None:
        return None
    doc = man.getFormatter().getPresentation(0).getDocument()
    text = TextDocumentUtil.getText(doc)
    #engctx.unloadProjects(True)
    return text

@jsonrpc
def get_method_decompiled_code(filepath, method_signature):
    """Get the decompiled code of the given method in the APK file, the passed in method_signature needs to be a fully-qualified signature
    Dex units use Java-style internal addresses to identify items:
    - package: Lcom/abc/
    - type: Lcom/abc/Foo;
    - method: Lcom/abc/Foo;->bar(I[JLjava/Lang/String;)V
    - field: Lcom/abc/Foo;->flag1:Z
    note filepath needs to be an absolute path
    """
    if not filepath or not method_signature:
        return None

    apk = getOrLoadApk(filepath)
    if apk is None:
        return None
    
    codeUnit = apk.getDex()
    method = codeUnit.getMethod(method_signature)
    decomp = DecompilerHelper.getDecompiler(codeUnit)
    if not decomp:
        print('Cannot acquire decompiler for unit: %s' % decomp)
        return

    if not decomp.decompileMethod(method.getSignature()):
        print('Failed decompiling method')
        return

    text = decomp.getDecompiledMethodText(method.getSignature())
    return text


@jsonrpc
def get_class_decompiled_code(filepath, class_signature):
    """Get the decompiled code of the given class in the APK file, the passed in class_signature needs to be a fully-qualified signature
    Dex units use Java-style internal addresses to identify items:
    - package: Lcom/abc/
    - type: Lcom/abc/Foo;
    - method: Lcom/abc/Foo;->bar(I[JLjava/Lang/String;)V
    - field: Lcom/abc/Foo;->flag1:Z
    note filepath needs to be an absolute path
    """
    if not filepath or not class_signature:
        return None

    apk = getOrLoadApk(filepath)
    if apk is None:
        return None
    
    codeUnit = apk.getDex()
    clazz = codeUnit.getClass(class_signature)
    decomp = DecompilerHelper.getDecompiler(codeUnit)
    if not decomp:
        print('Cannot acquire decompiler for unit: %s' % decomp)
        return

    if not decomp.decompileClass(clazz.getSignature()):
        print('Failed decompiling method')
        return

    text = decomp.getDecompiledClassText(clazz.getSignature())
    return text

from com.pnfsoftware.jeb.core.actions import ActionXrefsData, Actions, ActionContext

@jsonrpc
def get_method_callers(filepath, method_signature):
    """
    Get the callers of the given method in the APK file, the passed in method_signature needs to be a fully-qualified signature
    note filepath needs to be an absolute path
    """
    if not filepath or not method_signature:
        return None

    apk = getOrLoadApk(filepath)
    if apk is None:
        return None
    
    ret = []
    codeUnit = apk.getDex()
    method = codeUnit.getMethod(method_signature)
    if method is None:
        raise Exception("Method not found: %s" % method_signature)
    actionXrefsData = ActionXrefsData()
    actionContext = ActionContext(codeUnit, Actions.QUERY_XREFS, method.getItemId(), None)
    if codeUnit.prepareExecution(actionContext,actionXrefsData):
        for i in range(actionXrefsData.getAddresses().size()):
            ret.append((actionXrefsData.getAddresses()[i], actionXrefsData.getDetails()[i]))
    return ret

from com.pnfsoftware.jeb.core.actions import Actions, ActionContext, ActionOverridesData
@jsonrpc
def get_method_overrides(filepath, method_signature):
    """
    Get the overrides of the given method in the APK file, the passed in method_signature needs to be a fully-qualified signature
    note filepath needs to be an absolute path
    """
    if not filepath or not method_signature:
        return None

    apk = getOrLoadApk(filepath)
    if apk is None:
        return None
    
    ret = []
    codeUnit = apk.getDex()
    method = codeUnit.getMethod(method_signature)
    if method is None:
        raise Exception("Method not found: %s" % method_signature)
    data = ActionOverridesData()
    actionContext = ActionContext(codeUnit, Actions.QUERY_OVERRIDES, method.getItemId(), None)
    if codeUnit.prepareExecution(actionContext,data):
        for i in range(data.getAddresses().size()):
            ret.append((data.getAddresses()[i], data.getDetails()[i]))
    return ret

@jsonrpc
def get_native_libraries(filepath):
    """Get list of native libraries (.so files) in the APK"""
    if not filepath:
        return None

    apk = getOrLoadApk(filepath)
    if apk is None:
        print('[MCP] getOrLoadApk returned None, cannot find APK unit.')
        return None
    
    native_libs = []
    
    # Create a list of units to check, starting with the APK's direct children
    units_to_check = list(apk.getChildren())
    
    # Process units, including children of composite units
    processed_units = 0
    while processed_units < len(units_to_check):
        unit = units_to_check[processed_units]
        processed_units += 1

        unit_name = ''
        try:
            unit_name = unit.getName()
        except:
            # Fallback to parsing the string representation
            try:
                repr_str = repr(unit)
                if 'name={' in repr_str:
                    unit_name = repr_str.split('name={')[1].split('}')[0]
            except:
                pass # can't get name

        print('[MCP-DEBUG] Checking unit: %s' % unit_name)

        # Check if it's a native library
        is_native = 'elf' in str(unit.getFormatType()).lower() or isinstance(unit, INativeCodeUnit)
        if is_native:
            print('[MCP-DEBUG] Identified "%s" as a native unit (type: %s).' % (unit_name, unit.getFormatType()))
            
            arch = 'unknown'
            if hasattr(unit, 'getProcessor'):
                arch = str(unit.getProcessor())

            native_libs.append({
                'name': unit_name,
                'type': str(unit.getFormatType()),
                'architecture': arch
            })

        # If it's a composite unit (like 'Libraries'), add its children to the list to be checked
        if hasattr(unit, 'getChildren') and callable(unit.getChildren):
            try:
                # Add children to the list to be checked, avoiding infinite loops with self-references
                children = unit.getChildren()
                if children:
                    print('[MCP-DEBUG] Unit "%s" is composite, adding %d children to check queue.' % (unit_name, len(children)))
                    for child in children:
                        if child not in units_to_check:
                            units_to_check.append(child)
            except Exception as e:
                print('[MCP-DEBUG] Could not get children for unit %s: %s' % (unit_name, e))

    print('[MCP] Found %d native libraries after full check.' % len(native_libs))
    return native_libs

def _find_elf_unit(apk, lib_name):
    """Find the ELF container unit by name."""
    if not apk or not lib_name:
        return None

    units_to_check = list(apk.getChildren())
    
    processed_units = 0
    while processed_units < len(units_to_check):
        unit = units_to_check[processed_units]
        processed_units += 1

        unit_name = ''
        try:
            unit_name = unit.getName()
        except:
            try:
                repr_str = repr(unit)
                if 'name={' in repr_str:
                    unit_name = repr_str.split('name={')[1].split('}')[0]
            except:
                pass

        is_elf = 'elf' in str(unit.getFormatType()).lower()
        if is_elf and unit_name == lib_name:
            print('[MCP] Found ELF container for %s.' % lib_name)
            return unit

        if hasattr(unit, 'getChildren') and callable(unit.getChildren):
            try:
                children = unit.getChildren()
                if children:
                    for child in children:
                        if child not in units_to_check:
                            units_to_check.append(child)
            except Exception as e:
                print('[MCP-DEBUG] Could not get children for unit %s: %s' % (unit_name, e))

    print('[MCP] ELF unit not found after full check: %s' % lib_name)
    return None

def _get_native_code_unit(apk, lib_name):
    """Finds the ELF container and returns the primary native code unit within it."""
    elf_unit = _find_elf_unit(apk, lib_name)
    if not elf_unit:
        print('[MCP-WARN] _get_native_code_unit: Could not find ELF unit %s' % lib_name)
        return None

    # The ELF container holds the code unit (e.g., 'arm64 image') as a child.
    if hasattr(elf_unit, 'getChildren'):
        for child in elf_unit.getChildren():
            if isinstance(child, INativeCodeUnit):
                print('[MCP-DEBUG] Found native code unit: %s' % child.getName())
                return child
    
    # Fallback for older JEB versions or different structures
    if hasattr(elf_unit, 'getImageUnit'):
        image_unit = elf_unit.getImageUnit()
        if image_unit:
            print('[MCP-DEBUG] Found native code unit via getImageUnit(): %s' % image_unit.getName())
            return image_unit
            
    print('[MCP-WARN] Could not find a native code unit within ELF container: %s' % lib_name)
    return None

def _get_address_from_name_or_addr(unit, name_or_addr):
    """Helper to resolve a name or address string to a numerical address."""
    # If it's already a numeric address, convert it
    try:
        if isinstance(name_or_addr, int):
            return name_or_addr
        if isinstance(name_or_addr, str):
            if name_or_addr.startswith('0x'):
                return int(name_or_addr, 16)
            if name_or_addr.isdigit():
                return int(name_or_addr)
    except (ValueError, TypeError):
        pass

    # If not a numeric string, treat as a name and find it.
    print('[MCP-DEBUG] Address "%s" is not numeric, resolving as name.' % name_or_addr)
    target_name = str(name_or_addr)

    # Search in methods
    if hasattr(unit, 'getMethods'):
        for m in unit.getMethods():
            if hasattr(m, 'getName') and m.getName() == target_name:
                if hasattr(m, 'getAddress'):
                    addr = m.getAddress()
                    print('[MCP-DEBUG] Found name in methods. Raw address from getAddress(): %s (type: %s)' % (addr, type(addr)))

                    # If getAddress() returns a non-numeric string (like the name itself),
                    # try to get the numeric item ID instead.
                    if isinstance(addr, str) and not addr.isdigit() and not addr.startswith('0x'):
                        if hasattr(m, 'getItemId'):
                            try:
                                item_id = m.getItemId()
                                print('[MCP-DEBUG] Address was symbolic. Using getItemId() instead: %s' % item_id)
                                return item_id
                            except:
                                pass # Fall through if getItemId fails

                    # Prevent recursion if address is the same as the name
                    if str(addr) == target_name:
                        print('[MCP-WARN] Address of method "%s" is the method name itself. Cannot resolve to numeric address.' % target_name)
                        return None 
                    # Recursively call to handle if getAddress() returns a non-numeric string for some reason
                    return _get_address_from_name_or_addr(unit, str(addr))

    # Search in symbols as a fallback
    if hasattr(unit, 'getSymbols'):
        for s in unit.getSymbols():
            if hasattr(s, 'getName') and s.getName() == target_name:
                if hasattr(s, 'getAddress'):
                    addr = s.getAddress()
                    print('[MCP-DEBUG] Found name in symbols. Address: %s' % addr)
                    if str(addr) == target_name:
                         print('[MCP-WARN] Address of symbol "%s" is the symbol name itself. Cannot resolve to numeric address.' % target_name)
                         return None
                    return _get_address_from_name_or_addr(unit, str(addr))

    print('[MCP-WARN] Could not resolve name "%s" to an address.' % target_name)
    return None

@jsonrpc
def load_native_library(filepath, lib_name):
    """Load and analyze a specific native library from APK"""
    if not filepath or not lib_name:
        return None

    apk = getOrLoadApk(filepath)
    if apk is None:
        return None
    
    try:
        # Use the new helper to get the code unit directly
        code_unit = _get_native_code_unit(apk, lib_name)
        if code_unit:
            info = {
                'name': code_unit.getName() if hasattr(code_unit, 'getName') else lib_name,
                'type': str(code_unit.getFormatType()),
                'architecture': 'unknown',
                'entry_point': 'N/A',
                'base_address': 'N/A'
            }

            if hasattr(code_unit, 'getProcessor'):
                info['architecture'] = str(code_unit.getProcessor())
            
            # Use getAddress() on the entry point object
            if hasattr(code_unit, 'getEntryPoint') and code_unit.getEntryPoint():
                ep = code_unit.getEntryPoint()
                if hasattr(ep, 'getAddress'):
                    info['entry_point'] = str(ep.getAddress())

            if hasattr(code_unit, 'getImageBase'):
                info['base_address'] = hex(code_unit.getImageBase())

            return info

    except Exception as e:
        print('Error loading native library: %s' % str(e))
        traceback.print_exc()
    
    return None

@jsonrpc
def get_native_functions(filepath, lib_name):
    """Get list of functions from a native library using multiple discovery methods."""
    print('[MCP-DEBUG] --- ENTERING get_native_functions (Enhanced Function Discovery) ---')
    if not filepath or not lib_name:
        return []

    apk = getOrLoadApk(filepath)
    if apk is None:
        return []
    
    MAX_FUNCS = 500
    funcs = []
    
    try:
        # Get the native code unit
        unit = _get_native_code_unit(apk, lib_name)
        if not unit:
            print('[MCP-ERROR] Could not find native code unit for %s' % lib_name)
            return []
        
        print('[MCP-DEBUG] Found native code unit: %s' % repr(unit))
        
        # Method 1: Use getMethods() - most reliable for analyzed code
        if hasattr(unit, 'getMethods'):
            try:
                methods = unit.getMethods()
                if methods:
                    print('[MCP-DEBUG] Found %d methods using getMethods()' % len(methods))
                    for method in methods:
                        try:
                            name = method.getName() if hasattr(method, 'getName') else str(method)
                            addr = str(method.getAddress()) if hasattr(method, 'getAddress') else 'N/A'
                            
                            # Filter out empty or invalid names
                            if name and name.strip() and name != 'N/A':
                                funcs.append({'name': name, 'address': addr, 'source': 'methods'})
                                if len(funcs) >= MAX_FUNCS:
                                    break
                        except Exception as e:
                            print('[MCP-DEBUG] Error processing method: %s' % str(e))
                            
                    if len(funcs) > 0:
                        print('[MCP-DEBUG] Success! Found %d functions via getMethods()' % len(funcs))
                        return funcs
            except Exception as e:
                print('[MCP-DEBUG] getMethods() failed: %s' % str(e))
        
        # Method 2: Use getRoutines() - alternative method for functions
        if hasattr(unit, 'getRoutines'):
            try:
                routines = unit.getRoutines()
                if routines:
                    print('[MCP-DEBUG] Found %d routines using getRoutines()' % len(routines))
                    for routine in routines:
                        try:
                            name = routine.getName() if hasattr(routine, 'getName') else str(routine)
                            addr = str(routine.getAddress()) if hasattr(routine, 'getAddress') else 'N/A'
                            
                            if name and name.strip() and name != 'N/A':
                                funcs.append({'name': name, 'address': addr, 'source': 'routines'})
                                if len(funcs) >= MAX_FUNCS:
                                    break
                        except Exception as e:
                            print('[MCP-DEBUG] Error processing routine: %s' % str(e))
                            
                    if len(funcs) > 0:
                        print('[MCP-DEBUG] Success! Found %d functions via getRoutines()' % len(funcs))
                        return funcs
            except Exception as e:
                print('[MCP-DEBUG] getRoutines() failed: %s' % str(e))
        
        # Method 3: Enhanced symbol analysis with broader type matching
        if hasattr(unit, 'getSymbols'):
            try:
                symbols = unit.getSymbols()
                if symbols:
                    print('[MCP-DEBUG] Found %d symbols. Using enhanced symbol analysis...' % len(symbols))
                    for i, s in enumerate(symbols):
                        try:
                            s_name = s.getName() if hasattr(s, 'getName') else None
                            s_type = str(s.getType()) if hasattr(s, 'getType') else 'UNKNOWN'
                            s_addr_str = str(s.getAddress()) if hasattr(s, 'getAddress') else 'N/A'
                            
                            # More comprehensive type matching - include any symbol that looks like a function
                            is_function = (
                                'FUNCTION' in s_type.upper() or
                                'FUNC' in s_type.upper() or
                                'ROUTINE' in s_type.upper() or
                                'METHOD' in s_type.upper() or
                                'PROC' in s_type.upper() or
                                s_type in ['EXPORT', 'IMPORT', 'SYMBOL']  # Common symbol types that might be functions
                            )
                            
                            # Also check if the symbol name looks like a function (contains parentheses or common prefixes)
                            if s_name and not is_function:
                                name_lower = s_name.lower()
                                is_function = (
                                    '(' in s_name or
                                    name_lower.startswith('sub_') or
                                    name_lower.startswith('loc_') or
                                    name_lower.startswith('j_') or
                                    name_lower.startswith('nullsub_') or
                                    name_lower.startswith('_z') or  # Mangled C++ names
                                    name_lower.startswith('java_') or
                                    name_lower.startswith('jni_')
                                )
                            
                            if is_function and s_name and s_name.strip():
                                funcs.append({
                                    'name': str(s_name), 
                                    'address': s_addr_str,
                                    'type': s_type,
                                    'source': 'symbols'
                                })
                                if len(funcs) >= MAX_FUNCS:
                                    break
                                    
                        except Exception as e:
                            print('[MCP-DEBUG] Error processing symbol #%d: %s' % (i, str(e)))
                    
                    if len(funcs) > 0:
                        print('[MCP-DEBUG] Success! Found %d functions via enhanced symbol analysis' % len(funcs))
                        return funcs
                    else:
                        print('[MCP-DEBUG] No function symbols found with enhanced matching')
            except Exception as e:
                print('[MCP-DEBUG] Enhanced symbol analysis failed: %s' % str(e))
        
        # Method 4: Fallback - get all analyzed addresses that might be functions
        if hasattr(unit, 'getInstructions'):
            try:
                print('[MCP-DEBUG] Using fallback method: scanning for function entry points')
                instructions = unit.getInstructions()
                if instructions:
                    # Look for function prologues or entry points
                    func_candidates = []
                    for addr in instructions.getAddresses():
                        try:
                            insn = instructions.get(addr)
                            if insn and hasattr(insn, 'getMnemonic'):
                                mnemonic = insn.getMnemonic()
                                # Common function prologue patterns
                                if mnemonic in ['PUSH', 'SUB', 'MOV', 'ENTER']:
                                    func_candidates.append(addr)
                                    if len(func_candidates) >= MAX_FUNCS:
                                        break
                        except:
                            continue
                    
                    if func_candidates:
                        for i, addr in enumerate(func_candidates):
                            funcs.append({
                                'name': 'sub_%x' % addr,
                                'address': hex(addr),
                                'source': 'analysis'
                            })
                        print('[MCP-DEBUG] Found %d function candidates via instruction analysis' % len(funcs))
                        return funcs
            except Exception as e:
                print('[MCP-DEBUG] Instruction analysis failed: %s' % str(e))
        
        print('[MCP-DEBUG] All methods failed to find functions')
        return []
        
    except Exception as e:
        print('[MCP-ERROR] --- Unhandled exception in get_native_functions: %s ---' % str(e))
        traceback.print_exc()
        return []

@jsonrpc
def is_native_unit_processed(filepath, lib_name):
    """Check if the analysis of a native code unit is complete."""
    print('[MCP-DEBUG] Checking processing status for %s' % lib_name)
    try:
        apk = getOrLoadApk(filepath)
        if apk is None: return False
        
        # We must check the code unit, not the container
        unit = _get_native_code_unit(apk, lib_name)
        if not unit:
            print('[MCP-WARN] is_native_unit_processed: Could not find code unit %s' % lib_name)
            return False

        # The code unit has a reliable isProcessed() method.
        if hasattr(unit, 'isProcessed'):
            status = unit.isProcessed()
            print('[MCP-DEBUG] Code Unit %s isProcessed() returned: %s' % (unit.getName(), status))
            return status
        else:
            print('[MCP-WARN] Code Unit %s does not have an isProcessed() method.' % unit.getName())
            return False
            
    except Exception as e:
        print('[MCP-ERROR] is_native_unit_processed: Unhandled exception: %s' % str(e))
        return False

@jsonrpc
def process_native_unit(filepath, lib_name):
    """Programmatically start the analysis of a native code unit."""
    print('[MCP-DEBUG] Attempting to start processing for %s' % lib_name)
    try:
        apk = getOrLoadApk(filepath)
        if apk is None: return False
        
        unit = _get_native_code_unit(apk, lib_name)
        if not unit:
            print('[MCP-WARN] process_native_unit: Could not find unit %s' % lib_name)
            return False

        # The unit has a process() method to kick off analysis.
        if hasattr(unit, 'process'):
            print('[MCP-DEBUG] Calling process() on unit %s...' % lib_name)
            unit.process()
            return True
        else:
            print('[MCP-ERROR] Unit %s does not have a process() method.' % lib_name)
            return False
    except Exception as e:
        print('[MCP-ERROR] process_native_unit: Unhandled exception: %s' % str(e))
        return False

@jsonrpc
def decompile_native(filepath, lib_name, function_address):
    """Decompile a native function to C-like pseudocode"""
    if not filepath or not lib_name or not function_address:
        return None

    apk = getOrLoadApk(filepath)
    if apk is None:
        return None
    
    try:
        unit = _get_native_code_unit(apk, lib_name)
        if not unit:
            return "Could not find native code unit: %s" % lib_name
            
        decomp = DecompilerHelper.getDecompiler(unit)
        if not decomp:
            return "Decompiler not available for this native unit"
        
        # Find the method item (IMethod) by its name
        target_method = None
        if hasattr(unit, 'getMethods'):
            for m in unit.getMethods():
                # Use str() to handle potential unicode issues safely
                if str(m.getName()) == str(function_address):
                    target_method = m
                    print('[MCP-DEBUG] Found method item for decompilation: %s' % target_method)
                    break
        
        if target_method is None:
            return "Could not find a method item for function: %s" % function_address

        # Decompile using the method item itself, which is a valid INativeItem
        if decomp.decompile(target_method):
            source_unit = decomp.getDecompiledUnit()
            if source_unit and hasattr(source_unit, 'getDocument'):
                    return TextDocumentUtil.getText(source_unit.getDocument())
            return "Decompilation successful, but could not retrieve text."
        else:
            # Check for a common error when trying to decompile an imported/external function
            if target_method and not target_method.isInternal():
                return "Decompilation failed: Cannot decompile an external or imported function."
            return "Failed to decompile function: %s" % function_address
                    
    except Exception as e:
        print('Error decompiling native function: %s' % str(e))
        traceback.print_exc()
        return "Error: %s" % str(e)
    
    return "Could not find native unit or decompiler."

@jsonrpc
def get_native_strings(filepath, lib_name):
    """Get strings from a native library by reading its string table sections."""
    if not filepath or not lib_name:
        return []

    apk = getOrLoadApk(filepath)
    if apk is None:
        return []
    
    all_strings = []
    try:
        # To robustly find strings, we find the container unit for the library
        # and iterate through all of its sections, not just the processed code unit.
        elf_unit = _find_elf_unit(apk, lib_name)
        if not elf_unit:
            print('[MCP-ERROR] get_native_strings: Could not find ELF container unit for %s' % lib_name)
            return []

        if not hasattr(elf_unit, 'getSections'):
            print('[MCP-WARN] get_native_strings: ELF unit has no getSections method.')
            return []
            
        sections = elf_unit.getSections()
        if not sections:
            print('[MCP-WARN] get_native_strings: No sections found in ELF unit.')
            return []

        print("[MCP-DEBUG] Iterating all sections in ELF unit to find strings...")
        for sec in sections:
            sec_name = sec.getName() if hasattr(sec, 'getName') else 'N/A'
            try:
                # A section is likely to contain strings if its type indicates it,
                # or if its name is a common name for a string-containin section.
                is_str_sec = hasattr(sec, 'isStringSection') and sec.isStringSection()
                if is_str_sec or sec_name in ['.rodata', '.data', '.strtab', '.dynstr', '.rdata']:
                    if hasattr(sec, 'getStrings'):
                        string_list = sec.getStrings()
                        if string_list:
                            print("[MCP-DEBUG] Found %d strings in section: %s" % (len(string_list), sec_name))
                            for s in string_list:
                                if hasattr(s, 'getValue'):
                                    all_strings.append(s.getValue())
                                else: # Fallback
                                    all_strings.append(str(s))
            except Exception as e:
                # Some sections might fail this check, which is fine.
                print("[MCP-DEBUG] Could not get strings from section %s: %s" % (sec_name, e))

        return list(set(all_strings))

    except Exception as e:
        print('Error reading native strings: %s' % str(e))
        traceback.print_exc()
        return []

@jsonrpc
def find_native_xrefs(filepath, lib_name, address):
    """Find cross-references to a given native address."""
    if not filepath or not lib_name or not address:
        return None

    apk = getOrLoadApk(filepath)
    if apk is None:
        return None
    
    try:
        unit = _get_native_code_unit(apk, lib_name)
        if not unit:
            return "Could not find native unit for xrefs: %s" % lib_name
            
        ret = []
        
        # Find the method item (IMethod) by its name or address to get its ID
        target_item_id = None
        
        # Resolve name or address to a numerical address first
        resolved_addr = _get_address_from_name_or_addr(unit, address)
        if resolved_addr is None:
            return "Could not resolve address or name: %s" % address

        # Use JEB's cross-reference analysis with the resolved address/ID
        actionXrefsData = ActionXrefsData()
        # The third argument to ActionContext is the item ID or address
        actionContext = ActionContext(unit, Actions.QUERY_XREFS, resolved_addr, None)
        
        print('[MCP-DEBUG] Querying xrefs for item at address/id: %s' % resolved_addr)
        if unit.prepareExecution(actionContext, actionXrefsData):
            print('[MCP-DEBUG] Found %d xrefs.' % actionXrefsData.getAddresses().size())
            for i in range(actionXrefsData.getAddresses().size()):
                ret.append({
                    'address': str(actionXrefsData.getAddresses()[i]),
                    'details': str(actionXrefsData.getDetails()[i])
                })
        else:
            print('[MCP-DEBUG] prepareExecution for xrefs returned False.')

        return ret
            
    except Exception as e:
        print('Error finding native xrefs: %s' % str(e))
        traceback.print_exc()
        return "Error: %s" % str(e)

@jsonrpc
def get_native_imports(filepath, lib_name):
    """Get imported functions/libraries for native library by parsing symbol tables."""
    if not filepath or not lib_name:
        return []

    apk = getOrLoadApk(filepath)
    if apk is None: return []

    imports = []
    try:
        elf_unit = _find_elf_unit(apk, lib_name)
        if not elf_unit or not hasattr(elf_unit, 'getSections'):
            return []

        for sec in elf_unit.getSections():
            sec_name = sec.getName() if hasattr(sec, 'getName') else ''
            # Dynamic symbols section is the primary place for imports
            if sec_name == '.dynsym' and hasattr(sec, 'getSymbols'):
                print('[MCP-DEBUG] Parsing .dynsym section for imports...')
                for sym in sec.getSymbols():
                    # An undefined (UND) symbol in the dynamic table is an import
                    if hasattr(sym, 'isUndefined') and sym.isUndefined():
                        imports.append({
                            'name': sym.getName(),
                            'address': 'N/A' # Imports don't have an address in this context
                        })
        
        # If .dynsym didn't yield results, check the static symbol table as a fallback.
        if not imports:
             for sec in elf_unit.getSections():
                sec_name = sec.getName() if hasattr(sec, 'getName') else ''
                if sec_name == '.symtab' and hasattr(sec, 'getSymbols'):
                    print('[MCP-DEBUG] Parsing .symtab section for imports...')
                    for sym in sec.getSymbols():
                        if hasattr(sym, 'isUndefined') and sym.isUndefined():
                            imports.append({'name': sym.getName(), 'address': 'N/A'})

    except Exception as e:
        print('Error getting native imports: %s' % str(e))
        traceback.print_exc()

    if not imports:
        print('[MCP-WARN] Found no imports for %s after trying all methods.' % lib_name)
    else:
        print('[MCP-INFO] Found %d imports for %s.' % (len(imports), lib_name))

    return imports

@jsonrpc
def get_native_exports(filepath, lib_name):
    """Get exported functions from native library by parsing symbol tables."""
    if not filepath or not lib_name:
        return []

    apk = getOrLoadApk(filepath)
    if apk is None: return []

    exports = []
    try:
        elf_unit = _find_elf_unit(apk, lib_name)
        if not elf_unit or not hasattr(elf_unit, 'getSections'):
            return []

        # Exports are typically found in the .dynsym (dynamic) or .symtab (static) sections
        for sec in elf_unit.getSections():
            sec_name = sec.getName() if hasattr(sec, 'getName') else ''
            if sec_name in ['.dynsym', '.symtab'] and hasattr(sec, 'getSymbols'):
                print('[MCP-DEBUG] Parsing %s section for exports...' % sec_name)
                for sym in sec.getSymbols():
                    # Exports are defined symbols with global binding
                    is_defined = not (hasattr(sym, 'isUndefined') and sym.isUndefined())
                    is_global = hasattr(sym, 'isGlobal') and sym.isGlobal()
                    
                    if is_defined and is_global:
                        exports.append({
                            'name': sym.getName(),
                            'address': hex(sym.getValue()) if hasattr(sym, 'getValue') else 'N/A'
                        })

    except Exception as e:
        print('Error getting native exports: %s' % str(e))
        traceback.print_exc()
    
    if not exports:
        print('[MCP-WARN] Found no exports for %s after trying all methods.' % lib_name)
    else:
        # Use set to get unique exports, as symbols can appear in both tables
        unique_exports = list({v['name']:v for v in exports}.values())
        print('[MCP-INFO] Found %d unique exports for %s.' % (len(unique_exports), lib_name))
        return unique_exports

    return exports

@jsonrpc
def get_all_units(filepath):
    """Get all units and subunits for a given APK, for debugging."""
    if not filepath:
        return []

    apk = getOrLoadApk(filepath)
    if apk is None:
        return []
    
    units_info = []
    
    def collect_units(unit, depth=0):
        units_info.append({
            'name': unit.getName(),
            'type': unit.getFormatType(),
            'class': str(unit.getClass()),
            'depth': depth
        })
        for subunit in unit.getChildren():
            collect_units(subunit, depth + 1)
            
    collect_units(apk)
    return units_info

CTX = None

class MCP(IScript):

    def __init__(self):
        self.server = Server()
        global server
        server = self.server
        global CTX
        CTX = None
        print("[MCP] Plugin loaded")

    def run(self, ctx):
        """
        This is the entrypoint of the script.
        """
        global CTX
        CTX = ctx
        print('[MCP] Starting MCP server...')
        self.server.start()
        print("[MCP] Plugin running")

    def term(self):
        self.server.stop()
