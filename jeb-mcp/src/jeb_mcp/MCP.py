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

def get_native_unit(apk, lib_name):
    """Find a native code IMAGE unit by name in an APK unit."""
    elf_unit = _find_elf_unit(apk, lib_name)
    if elf_unit:
        if hasattr(elf_unit, 'getImageUnit'):
            image_unit = elf_unit.getImageUnit()
            if image_unit:
                print('[MCP] Returning image unit from ELF container for %s.' % lib_name)
                return image_unit
        print('[MCP] ELF unit for %s has no image unit, returning ELF unit itself.' % lib_name)
        return elf_unit
    
    print('[MCP] Native code unit not found for %s.' % lib_name)
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
        elf_unit = _find_elf_unit(apk, lib_name)
        if elf_unit:
            # The code unit is the 'image' inside the ELF container
            code_unit = elf_unit.getImageUnit() if hasattr(elf_unit, 'getImageUnit') else elf_unit

            info = {
                'name': elf_unit.getName() if hasattr(elf_unit, 'getName') else lib_name,
                'type': str(elf_unit.getFormatType()),
                'architecture': 'unknown',
                'entry_point': 'N/A',
                'base_address': 'N/A'
            }

            if code_unit and hasattr(code_unit, 'getProcessor'):
                info['architecture'] = str(code_unit.getProcessor())
            
            if code_unit and hasattr(code_unit, 'getEntryPoint') and code_unit.getEntryPoint():
                info['entry_point'] = str(code_unit.getEntryPoint())
            
            if code_unit and hasattr(code_unit, 'getImageBase'):
                info['base_address'] = str(code_unit.getImageBase())

            return info

    except Exception as e:
        print('Error loading native library: %s' % str(e))
        traceback.print_exc()
    
    return None

@jsonrpc
def get_native_functions(filepath, lib_name):
    """Get list of functions from the exported symbols of a native library."""
    if not filepath or not lib_name:
        return None

    apk = getOrLoadApk(filepath)
    if apk is None:
        return None
    
    try:
        # Exported functions are on the ELF container unit.
        unit = _find_elf_unit(apk, lib_name) 
        if not unit:
            return []

        functions = []
        
        # We use getExportedSymbols, as this was shown to contain the function names.
        if hasattr(unit, 'getExportedSymbols'):
            routines = unit.getExportedSymbols()
        else:
            print('[MCP-ERROR] The ELF unit does not have a getExportedSymbols() method.')
            return []
        
        if not routines:
            print('[MCP-DEBUG] getExportedSymbols() returned no routines.')
            return []

        for r in routines:
            address, name = None, None
            try:
                if hasattr(r, 'getAddress'):
                    address = str(r.getAddress())
            except Exception as e:
                print('[MCP-ERROR] Could not get address for a symbol: %s' % e)

            try:
                if hasattr(r, 'getName'):
                    name = r.getName()
            except Exception as e:
                print('[MCP-ERROR] Could not get name for a symbol: %s' % e)

            if address and name:
                functions.append({
                    'address': address,
                    'name': name
                })

        return functions
    except Exception as e:
        print('Error getting native functions: %s' % str(e))
        traceback.print_exc()
    
    return []

@jsonrpc
def decompile_native_function(filepath, lib_name, function_address):
    """Decompile a native function to C-like pseudocode"""
    if not filepath or not lib_name or not function_address:
        return None

    apk = getOrLoadApk(filepath)
    if apk is None:
        return None
    
    try:
        unit = get_native_unit(apk, lib_name) # This gets the imageUnit
        if unit:
            # Get decompiler for native code
            decomp = DecompilerHelper.getDecompiler(unit)
            if not decomp:
                return "Decompiler not available for this native unit"
            
            # Try to decompile the function at the given address
            try:
                # Convert address string to long for JEB API
                addr = long(function_address, 16) if isinstance(function_address, basestring) and function_address.startswith('0x') else long(function_address)
                
                # Decompile using the method's address (not signature)
                if decomp.decompile(addr):
                    # Use getDecompiledText to get the full output
                    source_unit = decomp.getDecompiledUnit()
                    if source_unit and hasattr(source_unit, 'getDocument'):
                         return TextDocumentUtil.getText(source_unit.getDocument())
                    return "Decompilation successful, but could not retrieve text."
                else:
                    return "Failed to decompile function at address: %s" % function_address
            except Exception as addr_e:
                return "Invalid address format or decompilation error: %s" % str(addr_e)
                    
    except Exception as e:
        print('Error decompiling native function: %s' % str(e))
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
    
    try:
        unit = _find_elf_unit(apk, lib_name) # Get the ELF container
        if not unit or not hasattr(unit, 'getSections'):
            return []
        
        all_strings = []
        sections = unit.getSections()
        if not sections:
            return []

        for section in sections:
            name = section.getName() if hasattr(section, 'getName') else ''
            
            # Target common string-containing sections
            if name in ['.rodata', '.rdata', '.strings', '.strtab', '.dynstr']:
                print("[MCP-DEBUG] Reading strings from section: %s" % name)
                if hasattr(section, 'getData'):
                    data_obj = section.getData()
                    if data_obj and hasattr(data_obj, 'getSize') and hasattr(data_obj, 'read'):
                        raw_bytes = data_obj.read(0, data_obj.getSize())
                        
                        # Find null-terminated ASCII strings
                        current_string = ""
                        for byte in raw_bytes:
                            if byte == '\x00':
                                # Min length 4 to filter out garbage
                                if len(current_string) > 3:
                                    all_strings.append(current_string)
                                current_string = ""
                            else:
                                # Check for printable characters
                                if 32 <= ord(byte) <= 126:
                                    current_string += byte
                                else:
                                    if len(current_string) > 3:
                                        all_strings.append(current_string)
                                    current_string = ""

        # Return unique strings
        return list(set(all_strings))

    except Exception as e:
        print('Error reading native strings from sections: %s' % str(e))
        traceback.print_exc()
    
    return []

@jsonrpc
def get_jni_methods(filepath):
    """Get JNI method mappings between Java and native code"""
    if not filepath:
        return None

    apk = getOrLoadApk(filepath)
    if apk is None:
        return None
    
    jni_methods = []
    try:
        # Get DEX unit for Java side
        dex_unit = apk.getDex()
        if not dex_unit:
            return []
        
        # Look for native methods in Java classes
        for java_class in dex_unit.getClasses():
            class_sig = java_class.getSignature()
            for method in java_class.getMethods():
                if hasattr(method, 'isNative') and method.isNative():
                    jni_methods.append({
                        'java_class': class_sig,
                        'java_method': method.getSignature(),
                        'method_name': method.getName(),
                        'is_native': True,
                        'jni_name': 'Java_%s_%s' % (class_sig.replace('/', '_').replace(';', '').replace('L', ''), method.getName())
                    })
    except Exception as e:
        print('Error getting JNI methods: %s' % str(e))
    
    return jni_methods

@jsonrpc
def find_native_xrefs(filepath, lib_name, address):
    """Find cross-references to/from a native address"""
    if not filepath or not lib_name or not address:
        return None

    apk = getOrLoadApk(filepath)
    if apk is None:
        return None
    
    try:
        unit = get_native_unit(apk, lib_name) # Gets the imageUnit
        if unit:
            ret = []
            try:
                addr = long(address, 16) if isinstance(address, basestring) and address.startswith('0x') else long(address)
                
                # Use JEB's cross-reference analysis
                actionXrefsData = ActionXrefsData()
                actionContext = ActionContext(unit, Actions.QUERY_XREFS, addr, None)
                if unit.prepareExecution(actionContext, actionXrefsData):
                    for i in range(actionXrefsData.getAddresses().size()):
                        ret.append({
                            'address': str(actionXrefsData.getAddresses()[i]),
                            'details': str(actionXrefsData.getDetails()[i])
                        })
                return ret
            except Exception as addr_e:
                return "Invalid address format: %s" % str(addr_e)
            
    except Exception as e:
        print('Error finding native xrefs: %s' % str(e))
        return "Error: %s" % str(e)

    return []

@jsonrpc
def get_native_imports(filepath, lib_name):
    """Get imported functions/libraries for native library"""
    if not filepath or not lib_name:
        return None

    apk = getOrLoadApk(filepath)
    if apk is None:
        return None

    try:
        # Imports are part of the ELF container format
        unit = _find_elf_unit(apk, lib_name)
        if unit and hasattr(unit, 'getImportedSymbols'):
            imports = []
            for imp in unit.getImportedSymbols():
                imports.append({
                    'name': imp.getName() if hasattr(imp, 'getName') else 'N/A'
                })
            return imports
    except Exception as e:
        print('Error getting native imports: %s' % str(e))
        traceback.print_exc()

    return []

@jsonrpc
def get_native_exports(filepath, lib_name):
    """Get exported functions from native library"""
    if not filepath or not lib_name:
        return None

    apk = getOrLoadApk(filepath)
    if apk is None:
        return None

    try:
        # Exports are part of the ELF container format
        unit = _find_elf_unit(apk, lib_name)
        if unit and hasattr(unit, 'getExportedSymbols'):
            exports = []
            for exp in unit.getExportedSymbols():
                exports.append({
                    'name': exp.getName() if hasattr(exp, 'getName') else 'N/A',
                    'address': str(exp.getAddress()) if hasattr(exp, 'getAddress') else None
                })
            return exports
    except Exception as e:
        print('Error getting native exports: %s' % str(e))
        traceback.print_exc()
    
    return []

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
