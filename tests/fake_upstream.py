"""A tiny OpenAI-compatible server for tests: echoes the last user message, can answer with a tool call,
streams when asked, and can be told to fail. Standard library only."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FakeUpstream:
    def __init__(self):
        self.requests = []
        self.fail_with = None        # (code, body) for the next request
        self.answer = None           # fixed content instead of the echo
        srv = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        srv.daemon_threads = True
        self.srv = srv
        self.url = "http://127.0.0.1:%d/v1" % srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()

    def _handler(self):
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or b"{}")
                fake.requests.append({"path": self.path, "headers": dict(self.headers), "body": body})
                if fake.fail_with:
                    code, msg = fake.fail_with
                    fake.fail_with = None
                    data = json.dumps({"error": {"message": msg}}).encode()
                    self.send_response(code)
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    return
                last = next((m for m in reversed(body.get("messages", [])) if m.get("role") == "user"), {"content": ""})
                content = fake.answer if fake.answer is not None else "echo: " + str(last.get("content"))
                msg = {"role": "assistant", "content": content}
                finish = "stop"
                if body.get("tools") and "call tool" in str(last.get("content", "")):
                    msg = {"role": "assistant", "content": None,
                           "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": body["tools"][0]["function"]["name"], "arguments": json.dumps({"q": str(last.get("content"))})}}]}
                    finish = "tool_calls"
                usage = {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
                if body.get("stream"):
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.end_headers()
                    words = (content or "").split(" ")
                    for i, w in enumerate(words):
                        delta = {"role": "assistant", "content": (" " if i else "") + w} if i == 0 or True else {}
                        self.wfile.write(("data: " + json.dumps({"id": "x", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": delta, "finish_reason": None}]}) + "\n\n").encode())
                    self.wfile.write(("data: " + json.dumps({"id": "x", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {}, "finish_reason": finish}]}) + "\n\n").encode())
                    self.wfile.write(("data: " + json.dumps({"id": "x", "object": "chat.completion.chunk", "choices": [], "usage": usage}) + "\n\n").encode())
                    self.wfile.write(b"data: [DONE]\n\n")
                    return
                data = json.dumps({"id": "x", "object": "chat.completion", "model": body.get("model"),
                                   "choices": [{"index": 0, "message": msg, "finish_reason": finish}], "usage": usage}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        return H
