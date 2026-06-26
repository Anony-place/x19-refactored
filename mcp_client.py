import json
import os
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Dict, List, Any, Callable

from config import CONFIG
from logging_utils import log


MCP_PROTOCOL_VERSION = "2024-11-05"


@dataclass
class MCPTool:
    name: str
    description: str = ""
    input_schema: dict = field(default_factory=dict)
    server: str = ""


@dataclass
class MCPResult:
    success: bool
    content: List[Dict[str, Any]] = field(default_factory=list)
    error: str = ""


class MCPServer:
    """Represents a connection to a single MCP server (stdio or TCP)."""

    def __init__(self, name: str, transport: str = "stdio",
                 command: Optional[List[str]] = None,
                 host: str = "127.0.0.1", port: int = 0,
                 auto_reconnect: bool = True):
        self.name = name
        self.transport = transport
        self.command = command or []
        self.host = host
        self.port = port
        self.auto_reconnect = auto_reconnect
        self._process: Optional[subprocess.Popen] = None
        self._socket: Optional[socket.socket] = None
        self._reader: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._pending: Dict[int, threading.Event] = {}
        self._responses: Dict[int, dict] = {}
        self._req_id = 0
        self._connected = False
        self._capabilities: dict = {}
        self._tools: Dict[str, MCPTool] = {}
        self._buffer = b""
        self._stop = False

    # ---- Connection ----

    def connect(self) -> bool:
        if self._connected:
            return True
        try:
            if self.transport == "stdio":
                return self._connect_stdio()
            elif self.transport == "tcp":
                return self._connect_tcp()
            else:
                log(f"[MCP:{self.name}] Unknown transport: {self.transport}")
                return False
        except Exception as e:
            log(f"[MCP:{self.name}] Connect failed: {e}")
            return False

    def _connect_stdio(self) -> bool:
        if not self.command:
            log(f"[MCP:{self.name}] No command for stdio transport")
            return False
        try:
            self._process = subprocess.Popen(
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                bufsize=0,
            )
            self._connected = True
            self._start_reader()
            ok = self._initialize()
            if ok:
                self._discover_tools()
            return ok
        except Exception as e:
            log(f"[MCP:{self.name}] stdio connect error: {e}")
            self.disconnect()
            return False

    def _connect_tcp(self) -> bool:
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.connect((self.host, self.port))
            self._socket.settimeout(30)
            self._connected = True
            self._start_reader()
            ok = self._initialize()
            if ok:
                self._discover_tools()
            return ok
        except Exception as e:
            log(f"[MCP:{self.name}] TCP connect error: {e}")
            self.disconnect()
            return False

    def disconnect(self):
        self._stop = True
        self._connected = False
        try:
            if self._process:
                self._process.terminate()
                self._process.wait(timeout=3)
        except Exception:
            pass
        try:
            if self._socket:
                self._socket.close()
        except Exception:
            pass
        self._process = None
        self._socket = None

    def reconnect(self) -> bool:
        self.disconnect()
        time.sleep(1)
        return self.connect()

    # ---- Message handling ----

    def _start_reader(self):
        self._stop = False
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self):
        while not self._stop:
            try:
                if self.transport == "stdio" and self._process:
                    chunk = self._process.stdout.read(4096)
                elif self.transport == "tcp" and self._socket:
                    chunk = self._socket.recv(4096)
                else:
                    time.sleep(0.05)
                    continue

                if not chunk:
                    time.sleep(0.05)
                    continue

                self._buffer += chunk

                while b"\n" in self._buffer:
                    line, self._buffer = self._buffer.split(b"\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        msg = json.loads(line.decode("utf-8"))
                        self._handle_message(msg)
                    except json.JSONDecodeError:
                        pass
            except Exception as e:
                if not self._stop:
                    log(f"[MCP:{self.name}] Reader error: {e}")
                    time.sleep(0.1)

    def _send(self, msg: dict):
        payload = json.dumps(msg).encode("utf-8") + b"\n"
        try:
            if self.transport == "stdio" and self._process:
                self._process.stdin.write(payload)
                self._process.stdin.flush()
            elif self.transport == "tcp" and self._socket:
                self._socket.sendall(payload)
        except Exception as e:
            log(f"[MCP:{self.name}] Send error: {e}")
            if self.auto_reconnect:
                self.reconnect()

    def _send_request(self, method: str, params: dict = None) -> Optional[dict]:
        with self._lock:
            self._req_id += 1
            req_id = self._req_id
            event = threading.Event()
            self._pending[req_id] = event

        msg = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": params or {},
        }
        self._send(msg)

        event.wait(timeout=15)
        with self._lock:
            resp = self._responses.pop(req_id, None)
            self._pending.pop(req_id, None)

        if resp is None:
            log(f"[MCP:{self.name}] Request timeout: {method}")
        return resp

    def _handle_message(self, msg: dict):
        msg_id = msg.get("id")
        if msg_id is not None:
            with self._lock:
                event = self._pending.get(msg_id)
                if event:
                    self._responses[msg_id] = msg
                    event.set()
                    return

        method = msg.get("method", "")
        if method == "notifications/tools/list_changed":
            self._discover_tools()

    # ---- MCP Protocol methods ----

    def _initialize(self) -> bool:
        params = {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "clientInfo": {"name": "x19-mcp", "version": "1.0"},
        }
        resp = self._send_request("initialize", params)
        if resp and "result" in resp:
            self._capabilities = resp["result"].get("capabilities", {})
            log(f"[MCP:{self.name}] Initialized")
            return True
        log(f"[MCP:{self.name}] Initialize failed: {resp}")
        return False

    def _discover_tools(self):
        resp = self._send_request("tools/list")
        if resp and "result" in resp:
            tools_raw = resp["result"].get("tools", [])
            for t in tools_raw:
                tool = MCPTool(
                    name=t["name"],
                    description=t.get("description", ""),
                    input_schema=t.get("inputSchema", {}),
                    server=self.name,
                )
                self._tools[t["name"]] = tool
            log(f"[MCP:{self.name}] Discovered {len(self._tools)} tools")
        else:
            log(f"[MCP:{self.name}] tools/list failed: {resp}")

    def call_tool(self, name: str, arguments: dict = None) -> MCPResult:
        if name not in self._tools:
            return MCPResult(success=False, error=f"Tool '{name}' not found on {self.name}")

        if not self._connected:
            if not self.connect():
                return MCPResult(success=False, error=f"Cannot connect to {self.name}")

        params = {"name": name, "arguments": arguments or {}}
        resp = self._send_request("tools/call", params)

        if resp is None:
            return MCPResult(success=False, error=f"Timeout calling '{name}' on {self.name}")

        if "error" in resp:
            err = resp["error"].get("message", str(resp["error"]))
            return MCPResult(success=False, error=err)

        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content = result.get("content", [])
        return MCPResult(success=not is_error, content=content)

    @property
    def tools(self) -> List[MCPTool]:
        return list(self._tools.values())

    @property
    def connected(self) -> bool:
        return self._connected


class MCPClient:
    """Manages multiple MCP server connections and exposes unified tool access."""

    def __init__(self):
        self._servers: Dict[str, MCPServer] = {}
        self._config_path = Path(CONFIG.CONFIG_DIR) / "mcp_servers.json" if hasattr(CONFIG, "CONFIG_DIR") else None
        self._load_config()

    def add_server(self, name: str, transport: str = "stdio",
                   command: Optional[List[str]] = None,
                   host: str = "127.0.0.1", port: int = 0,
                   auto_connect: bool = True) -> MCPServer:
        server = MCPServer(
            name=name, transport=transport,
            command=command, host=host, port=port,
        )
        self._servers[name] = server
        if auto_connect:
            server.connect()
        self._save_config()
        return server

    def remove_server(self, name: str):
        server = self._servers.pop(name, None)
        if server:
            server.disconnect()
        self._save_config()

    def get_server(self, name: str) -> Optional[MCPServer]:
        return self._servers.get(name)

    def connect_all(self):
        for name, server in self._servers.items():
            if not server.connected:
                server.connect()

    def disconnect_all(self):
        for server in self._servers.values():
            server.disconnect()

    def call_tool(self, server_name: str, tool_name: str, arguments: dict = None) -> MCPResult:
        server = self._servers.get(server_name)
        if not server:
            return MCPResult(success=False, error=f"Unknown MCP server: {server_name}")
        return server.call_tool(tool_name, arguments)

    def call_first_match(self, tool_name: str, arguments: dict = None) -> MCPResult:
        for name, server in self._servers.items():
            if tool_name in server._tools:
                result = server.call_tool(tool_name, arguments)
                if result.success:
                    return result
        return MCPResult(success=False, error=f"Tool '{tool_name}' not found on any server")

    @property
    def all_tools(self) -> List[Dict]:
        tools_list = []
        for sname, server in self._servers.items():
            for tool in server.tools:
                tools_list.append({
                    "server": sname,
                    "name": tool.name,
                    "description": tool.description,
                    "input_schema": tool.input_schema,
                })
        return tools_list

    def tools_context_block(self) -> str:
        if not self._servers:
            return ""
        parts = ["MCP SERVERS & TOOLS:"]
        for sname, server in self._servers.items():
            status = "connected" if server.connected else "disconnected"
            tools = server.tools
            parts.append(f"  [{sname}] ({status}) — {len(tools)} tools:")
            for t in tools[:10]:
                desc = t.description[:80] if t.description else ""
                params = list(t.input_schema.get("properties", {}).keys()) if t.input_schema else []
                param_str = ", ".join(params[:5]) if params else ""
                parts.append(f"    => {t.name}({param_str}) {desc}")
            if len(tools) > 10:
                parts.append(f"    ... and {len(tools)-10} more")
        return "\n".join(parts)

    def _save_config(self):
        if not self._config_path:
            return
        try:
            data = {}
            for name, server in self._servers.items():
                data[name] = {
                    "transport": server.transport,
                    "command": server.command,
                    "host": server.host,
                    "port": server.port,
                }
            self._config_path.parent.mkdir(parents=True, exist_ok=True)
            self._config_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception as e:
            log(f"[MCP] Config save failed: {e}")

    def _load_config(self):
        if not self._config_path or not self._config_path.exists():
            return
        try:
            data = json.loads(self._config_path.read_text(encoding="utf-8"))
            for name, cfg in data.items():
                self.add_server(
                    name=name,
                    transport=cfg.get("transport", "stdio"),
                    command=cfg.get("command"),
                    host=cfg.get("host", "127.0.0.1"),
                    port=cfg.get("port", 0),
                    auto_connect=True,
                )
        except Exception as e:
            log(f"[MCP] Config load failed: {e}")
