#!/usr/bin/python3
"""UAT MCP stdio client — drives `agentcordon mcp-serve` over pipes.

Harness infrastructure. It stands in for "an agent runtime spawned the CLI as
an MCP server"; nothing here is a product claim. It speaks the client half of
newline-delimited JSON-RPC 2.0 over stdin/stdout, which is the transport
`agentcordon mcp-serve` documents.

By default it runs

    docker exec -i -w <workdir> <container> agentcordon mcp-serve [--expose S]…

so the CLI's stdin really is a pipe (`-i`), exactly as a runtime's MCP client
would spawn it. `--command` replaces that with any command line, which is how
the same client can be pointed at a locally built binary.

Input  (stdin): a JSON array of requests, each `{"method": …, "params": {…}}`.
                `params` is optional. `initialize` and `notifications/initialized`
                are performed by this client and must not appear in the array.
Output (stdout): one JSON object

    {
      "ok":            true | false,
      "argv":          [...],                 the command line that was run
      "initialize":    {...} | null,          the `result` of initialize
      "initialize_error": {...} | null,
      "responses":     [ {...}, ... ],        one JSON-RPC envelope per request
      "notifications": [ {...}, ... ],        server-initiated messages, in order
      "stderr":        "…",                   the server's log stream
      "exit_code":     int | null,
      "error":         "…" | null             harness-level failure, if any
    }

Every response is returned as its full envelope (`result` or `error`), so the
caller asserts on what the wire actually carried.

Usage:
  python3 uat/mcp_client.py [--container NAME] [--workdir DIR]
                            [--expose SERVER]… [--timeout SECONDS]
                            [--command CMD ARG…]      (must come last)
"""

import json
import os
import queue
import subprocess
import sys
import threading

DEFAULT_CONTAINER = os.environ.get("UAT_CLI", "agentcordon-uat-cli")
DEFAULT_WORKDIR = os.environ.get("UAT_SHIM_WORKDIR", "/home/uat/workspace")

# The revision of the MCP specification this client speaks. A server is free to
# answer with a different one it supports; nothing here asserts on the value.
PROTOCOL_VERSION = "2025-06-18"


def parse_args(argv):
    opts = {
        "container": DEFAULT_CONTAINER,
        "workdir": DEFAULT_WORKDIR,
        "expose": [],
        "timeout": 30.0,
        "command": None,
    }
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--container":
            opts["container"] = argv[i + 1]
            i += 2
        elif arg == "--workdir":
            opts["workdir"] = argv[i + 1]
            i += 2
        elif arg == "--expose":
            opts["expose"].append(argv[i + 1])
            i += 2
        elif arg == "--timeout":
            opts["timeout"] = float(argv[i + 1])
            i += 2
        elif arg == "--command":
            opts["command"] = argv[i + 1 :]
            if not opts["command"]:
                raise SystemExit("--command needs a command line after it")
            break
        else:
            raise SystemExit("unknown flag: %s" % arg)
    return opts


def build_argv(opts):
    if opts["command"]:
        argv = list(opts["command"])
        for server in opts["expose"]:
            argv += ["--expose", server]
        return argv
    argv = [
        "docker",
        "exec",
        "-i",
        "-w",
        opts["workdir"],
        opts["container"],
        "agentcordon",
        "mcp-serve",
    ]
    for server in opts["expose"]:
        argv += ["--expose", server]
    return argv


class Session:
    """One spawned `mcp-serve` process, spoken to over its pipes."""

    def __init__(self, argv, timeout):
        self.argv = argv
        self.timeout = timeout
        self.messages = queue.Queue()
        self.notifications = []
        self.unparsed = []
        self.stderr_chunks = []
        self.proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._readers = [
            threading.Thread(target=self._read_stdout, daemon=True),
            threading.Thread(target=self._read_stderr, daemon=True),
        ]
        for t in self._readers:
            t.start()

    def _read_stdout(self):
        for line in self.proc.stdout:
            text = line.decode("utf-8", "replace").strip()
            if not text:
                continue
            try:
                self.messages.put(json.loads(text))
            except ValueError:
                # A server that writes anything but JSON-RPC to stdout has
                # broken the transport; keep it so the failure is legible.
                self.unparsed.append(text)
        self.messages.put(None)  # stdout closed

    def _read_stderr(self):
        for line in self.proc.stderr:
            self.stderr_chunks.append(line.decode("utf-8", "replace"))

    def send(self, message):
        self.proc.stdin.write((json.dumps(message) + "\n").encode("utf-8"))
        self.proc.stdin.flush()

    def await_id(self, want_id):
        """The next message carrying `want_id`; notifications are collected."""
        while True:
            try:
                message = self.messages.get(timeout=self.timeout)
            except queue.Empty:
                raise TimeoutError(
                    "no response to id %s within %.0fs" % (want_id, self.timeout)
                )
            if message is None:
                raise EOFError("the server closed stdout before answering id %s" % want_id)
            if message.get("id") == want_id:
                return message
            if "id" not in message:
                self.notifications.append(message)
            else:
                # A response to an id nobody is waiting for. Keep it visible.
                self.notifications.append(message)

    def drain(self, seconds=0.5):
        """Collect anything the server volunteered before it is shut down."""
        deadline = seconds
        while deadline > 0:
            try:
                message = self.messages.get(timeout=0.1)
            except queue.Empty:
                deadline -= 0.1
                continue
            if message is None:
                return
            self.notifications.append(message)

    def close(self):
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        try:
            return self.proc.wait(timeout=self.timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            return self.proc.wait(timeout=5)


def main(argv):
    opts = parse_args(argv)
    raw = sys.stdin.read().strip()
    requests = json.loads(raw) if raw else []
    if not isinstance(requests, list):
        raise SystemExit("stdin must be a JSON array of requests")

    command = build_argv(opts)
    out = {
        "ok": False,
        "argv": command,
        "initialize": None,
        "initialize_error": None,
        "responses": [],
        "notifications": [],
        "unparsed_stdout": [],
        "stderr": "",
        "exit_code": None,
        "error": None,
    }

    try:
        session = Session(command, opts["timeout"])
    except OSError as exc:
        out["error"] = "could not start %r: %s" % (command, exc)
        print(json.dumps(out, indent=2))
        return 0

    try:
        session.send(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "uat-mcp-client", "version": "1"},
                },
            }
        )
        envelope = session.await_id(1)
        out["initialize"] = envelope.get("result")
        out["initialize_error"] = envelope.get("error")
        session.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

        next_id = 2
        for request in requests:
            message = {
                "jsonrpc": "2.0",
                "id": next_id,
                "method": request["method"],
            }
            if request.get("params") is not None:
                message["params"] = request["params"]
            session.send(message)
            out["responses"].append(session.await_id(next_id))
            next_id += 1

        session.drain()
        out["ok"] = out["initialize_error"] is None
    except (TimeoutError, EOFError, OSError, ValueError, KeyError) as exc:
        out["error"] = "%s: %s" % (type(exc).__name__, exc)
    finally:
        out["exit_code"] = session.close()
        out["notifications"] = session.notifications
        out["unparsed_stdout"] = session.unparsed
        out["stderr"] = "".join(session.stderr_chunks)

    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
