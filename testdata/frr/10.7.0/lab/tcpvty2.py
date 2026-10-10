# Raw FRR vty-over-TCP query for the local lab. Run inside a router netns.
# Usage: python3 -I tcpvty2.py PORT "command"
# Writes the daemon's bytes for that one command to stdout, unmodified.
import socket
import sys

port = int(sys.argv[1])
cmd = sys.argv[2]
s = socket.create_connection(("127.0.0.1", port), timeout=5)


def drain(quiet):
    s.settimeout(quiet)
    buf = b""
    while True:
        try:
            chunk = s.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
    return buf


drain(1.5)  # greeting and prompt, discarded
s.sendall(b"terminal length 0\n")
drain(0.6)
s.sendall(cmd.encode() + b"\n")
sys.stdout.buffer.write(drain(1.0))
s.close()
