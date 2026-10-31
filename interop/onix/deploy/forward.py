"""Forward 127.0.0.1:LOCAL to HOST:PORT. The runner talks only to loopback; an adapter running in WSL or a
container is reached through this. usage: forward.py LOCAL HOST PORT"""
import socket
import sys
import threading


def pump(a, b):
    try:
        while (d := a.recv(65536)):
            b.sendall(d)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def main(local, host, port):
    srv = socket.create_server(("127.0.0.1", int(local)))
    while True:
        c, _ = srv.accept()
        try:
            u = socket.create_connection((host, int(port)), timeout=10)
        except OSError:
            c.close()
            continue
        threading.Thread(target=pump, args=(c, u), daemon=True).start()
        threading.Thread(target=pump, args=(u, c), daemon=True).start()


if __name__ == "__main__":
    main(*sys.argv[1:4])
