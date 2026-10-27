"""Run an ASGI app with uvicorn on 127.0.0.1:<ephemeral> in a background thread."""
import socket
import threading
import time

import uvicorn


class ServerThread:
    def __init__(self, host="127.0.0.1"):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((host, 0))  # loopback only, OS-chosen port
        self.port = self.sock.getsockname()[1]
        self.url = f"http://{host}:{self.port}"
        self._server = None
        self._thread = None

    def start(self, app):
        config = uvicorn.Config(app, log_level="warning", lifespan="off", access_log=False)
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self._server.run, kwargs={"sockets": [self.sock]},
                                        daemon=True, name=f"uvicorn-{self.port}")
        self._thread.start()
        deadline = time.monotonic() + 10
        while not self._server.started:
            if time.monotonic() > deadline or not self._thread.is_alive():
                raise RuntimeError(f"server on {self.url} failed to start")
            time.sleep(0.01)
        return self

    def stop(self):
        if self._server:
            self._server.should_exit = True
        if self._thread:
            self._thread.join(timeout=10)
        self.sock.close()
