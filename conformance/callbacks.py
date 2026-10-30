"""Local receiver for the system under test's asynchronous `on_*` callbacks.

Beckn 2.0 answers every request with a synchronous Ack and delivers the result later as a signed POST
to `context.bapUri` + `/on_<action>`. This listener is that URL for the runner: a node checks
`bapUri` against the URL registered for the harness identity, so the operator registers
`http://127.0.0.1:<port>` and the runner listens on exactly that port. It is deliberately narrow:

- it binds 127.0.0.1 only, so it can be used against a node on the same machine (or one that can reach
  this machine's loopback, such as a container with host networking); a remote node needs a different
  design (a public callback URL) that this module does not provide;
- it accepts a callback only for a messageId the runner has just registered with `expect`, and only
  once, so unsolicited and replayed deliveries are refused;
- the callback's Authorization must be a chained signature (`(created) (expires) digest
  request-signature`) over the received body, chained to the signature the runner sent, by a key the
  operator supplied (`sut_keys`). Keys named in the callback are never fetched.

The Ack it returns is not signed (UNVERIFIED whether a node requires a signed Ack from the callback
receiver). Every verdict is recorded so a scenario can say why a callback was refused.
"""
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import signing

MAX_BODY_BYTES = 1_048_576
MAX_RECORDS = 1000
_PATH = re.compile(r"/(on_[a-z]+(?:_[a-z]+)*)")


class CallbackListener:
    def __init__(self, sut_keys, port=0, now=None):
        self.sut_keys = dict(sut_keys or {})
        self._now = now
        self._cond = threading.Condition()
        self._pending = {}   # messageId -> signature of the request it answers
        self._records = {}   # messageId -> first verdict {ok, action, error, body}
        self._ready = set()  # messageIds whose reply has been written; wait() returns only for these
        listener = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                listener._handle(self)

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    # ------------------------------------------------------------ runner side
    def expect(self, message_id, request_signature):
        with self._cond:
            if len(self._pending) >= MAX_RECORDS:
                self._pending.pop(next(iter(self._pending)))
            self._pending[message_id] = request_signature

    def wait(self, message_id, timeout):
        """The first verdict for `message_id`, or None if nothing (valid or not) arrived in `timeout` s."""
        with self._cond:
            self._cond.wait_for(lambda: message_id in self._ready, timeout)
            return self._records.get(message_id) if message_id in self._ready else None

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self._thread.join(timeout=5)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # ------------------------------------------------------------ server side
    def _reply(self, h, status, body):
        raw = json.dumps(body, separators=(",", ":")).encode()
        h.send_response(status)
        h.send_header("Content-Type", "application/json")
        h.send_header("Content-Length", str(len(raw)))
        h.end_headers()
        h.wfile.write(raw)

    def _nack(self, h, status, code, message, mid=None):
        self._reply(h, status, {"message": {"status": "NACK", "messageId": mid,
                                            "error": {"code": code, "message": message}}})

    def _handle(self, h):
        declared = h.headers.get("Content-Length", "")
        if not declared.isdigit() or int(declared) > MAX_BODY_BYTES:
            h.close_connection = True  # do not read what we are refusing
            return self._nack(h, 413, "SCH_INVALID_JSON", "body missing a length or over the limit")
        raw = h.rfile.read(int(declared))
        m = _PATH.fullmatch(h.path)
        if not m:
            return self._nack(h, 404, "SCH_INVALID_PATH", "only /on_<action> is served")
        action = m.group(1)
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            return self._nack(h, 400, "SCH_INVALID_JSON", "body is not valid UTF-8 JSON")
        ctx = doc.get("context") if isinstance(doc, dict) else None
        mid = ctx.get("messageId") if isinstance(ctx, dict) else None
        if not isinstance(mid, str):
            return self._nack(h, 400, "CTX_MISSING_FIELD", "context.messageId is required")
        with self._cond:
            request_sig = self._pending.get(mid)
            seen = mid in self._records
        if request_sig is None or seen:
            return self._nack(h, 400, "AUT_REPLAY_DETECTED" if seen else "BIZ_UNSOLICITED",
                              "already received" if seen else "no request with this messageId is awaiting a callback", mid)
        error = None
        if ctx.get("action") != action:
            error = f"path {action!r} does not match context.action {ctx.get('action')!r}"
            status, code = 400, "CTX_INVALID_FIELD"
        else:
            status, code = 401, "AUT_SIGNATURE_INVALID"
            try:
                signing.check_callback(h.headers.get("Authorization"), raw, request_sig, self.sut_keys, self._now)
            except signing.ResponseSignatureError as e:
                error = str(e)
        with self._cond:
            if mid in self._records:  # a concurrent delivery got there first
                return self._nack(h, 400, "AUT_REPLAY_DETECTED", "already received", mid)
            if len(self._records) >= MAX_RECORDS:
                self._ready.discard(next(iter(self._records)))
                self._records.pop(next(iter(self._records)))
            self._records[mid] = {"ok": error is None, "action": action, "error": error or "",
                                  "body": doc if error is None else None}
        try:
            if error:
                return self._nack(h, status, code, error, mid)
            self._reply(h, 200, {"message": {"status": "ACK", "messageId": mid}})
        finally:
            # Publish only once the reply is out: the runner closes the listener as soon as wait() returns.
            with self._cond:
                self._ready.add(mid)
                self._cond.notify_all()
