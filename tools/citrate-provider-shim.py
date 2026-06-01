#!/usr/bin/env python3
"""
citrate-provider-shim — Provider Protocol v1 ↔ OpenAI chat-completions bridge.

The citrate-inference-gateway dispatches inference jobs by POSTing
`ProviderProtocolRequest { model, prompt, max_tokens }` to whatever URL the
provider registered on `InferenceRouter`. The DGX Spark we registered runs
llama-server, which speaks OpenAI `/v1/chat/completions` (with a `messages`
list, not a flat `prompt`). This shim sits between them: it accepts the
gateway's POST, translates it to OpenAI shape, calls the upstream
llama-server, and repackages the response as a
`ProviderProtocolResponse { output, input_tokens, output_tokens }`.

Stdlib-only on purpose (no pip install needed). Run as a systemd unit
behind Caddy on the RPC droplet. Configuration via env vars:

  CITRATE_SHIM_LISTEN_ADDR   default 127.0.0.1:9000
  CITRATE_SHIM_UPSTREAM_URL  default http://100.68.173.64:8181  (DGX via tailnet)
  CITRATE_SHIM_MODEL_NAME    default gemma-4-E4B-it-Q4_K_M
  CITRATE_SHIM_TIMEOUT_SEC   default 120
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import sys
import urllib.request
import urllib.error


LISTEN_ADDR = os.environ.get("CITRATE_SHIM_LISTEN_ADDR", "127.0.0.1:9000")
UPSTREAM_URL = os.environ.get(
    "CITRATE_SHIM_UPSTREAM_URL", "http://100.68.173.64:8181"
)
MODEL_NAME = os.environ.get("CITRATE_SHIM_MODEL_NAME", "gemma-4-E4B-it-Q4_K_M")
TIMEOUT_SEC = int(os.environ.get("CITRATE_SHIM_TIMEOUT_SEC", "120"))


def _read_json(body: bytes) -> dict:
    return json.loads(body.decode("utf-8"))


def _write_json(handler: BaseHTTPRequestHandler, status: int, payload: dict) -> None:
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("content-type", "application/json")
    handler.send_header("content-length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def call_upstream(req: dict) -> dict:
    """POST OpenAI chat-completions to upstream llama-server, return parsed JSON."""
    body = json.dumps(req).encode("utf-8")
    url = UPSTREAM_URL.rstrip("/") + "/v1/chat/completions"
    http_req = urllib.request.Request(
        url, data=body, headers={"content-type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(http_req, timeout=TIMEOUT_SEC) as r:
        return json.loads(r.read())


def translate_to_openai(prov_req: dict) -> dict:
    """Provider Protocol v1 → OpenAI chat-completions."""
    return {
        # ProviderProtocolRequest's `model` is opaque to us — pin the real
        # model name the upstream llama-server expects. llama-server actually
        # ignores `model` since it has one loaded; we set it for clarity.
        "model": MODEL_NAME,
        "messages": [
            {"role": "user", "content": prov_req.get("prompt", "")},
        ],
        "max_tokens": int(prov_req.get("max_tokens", 256)),
    }


def translate_from_openai(openai_resp: dict) -> dict:
    """OpenAI chat-completions response → ProviderProtocolResponse.

    Gemma 4 with `--jinja` chat template emits a `reasoning_content`
    channel first (its CoT), then `content` (the answer). With small
    max_tokens budgets the whole budget can be consumed by reasoning
    and `content` comes back empty. For Provider Protocol v1 we want
    the text the caller actually sees — if `content` is empty, fall
    back to the trailing portion of `reasoning_content` so the gateway
    isn't handed an empty string.
    """
    msg = {}
    try:
        msg = openai_resp["choices"][0]["message"] or {}
    except (KeyError, IndexError, TypeError):
        pass
    content = (msg.get("content") or "").strip()
    if not content:
        # Gemma may park the whole answer in reasoning_content if max_tokens
        # was tight. Use it as the user-visible output instead of empty.
        content = (msg.get("reasoning_content") or "").strip()
    usage = openai_resp.get("usage") or {}
    return {
        "output": content,
        # ProviderProtocolResponse names them input_tokens / output_tokens,
        # OpenAI names them prompt_tokens / completion_tokens.
        "input_tokens": usage.get("prompt_tokens"),
        "output_tokens": usage.get("completion_tokens"),
    }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        # Send access log to stderr (systemd journal).
        sys.stderr.write("%s - - [%s] %s\n" % (
            self.address_string(), self.log_date_time_string(), fmt % args
        ))

    def do_GET(self):
        if self.path in ("/health", "/healthz"):
            _write_json(self, 200, {"ok": True})
            return
        _write_json(self, 404, {"error": "not found"})

    def do_POST(self):
        if not (self.path.endswith("/infer") or self.path.endswith("/v1")):
            _write_json(self, 404, {"error": f"not found: {self.path}"})
            return

        length = int(self.headers.get("content-length", "0"))
        raw = self.rfile.read(length)
        try:
            prov_req = _read_json(raw)
        except Exception as e:
            _write_json(self, 400, {"error": f"invalid json: {e}"})
            return

        openai_req = translate_to_openai(prov_req)
        try:
            openai_resp = call_upstream(openai_req)
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")[:400]
            _write_json(self, 502, {"error": f"upstream {e.code}: {body}"})
            return
        except urllib.error.URLError as e:
            _write_json(self, 502, {"error": f"upstream unreachable: {e.reason}"})
            return
        except Exception as e:
            _write_json(self, 500, {"error": f"shim error: {e}"})
            return

        prov_resp = translate_from_openai(openai_resp)
        _write_json(self, 200, prov_resp)


def main() -> int:
    host, _, port_s = LISTEN_ADDR.rpartition(":")
    port = int(port_s)
    addr = (host or "127.0.0.1", port)
    print(
        f"citrate-provider-shim listening on {addr[0]}:{addr[1]} "
        f"-> {UPSTREAM_URL} (model={MODEL_NAME}, timeout={TIMEOUT_SEC}s)",
        file=sys.stderr,
    )
    server = ThreadingHTTPServer(addr, Handler)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
