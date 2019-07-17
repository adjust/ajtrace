import logging
import socket
import time

from settings import GlobalConfig


class GraphiteBackend:
    def __init__(self, host, port):
        self.host = host
        self.port = port

    def connect(self):
        self.sock = socket.socket()
        self.sock.connect((self.host, self.port))

    def store(self, metric, value, timestamp=None):
        prefix = GlobalConfig.get('prefix', 'ajtest')

        msg = '{}.{} {} {}\n'.format(
                prefix,
                metric,
                value,
                timestamp if timestamp else int(time.time()))

        self.sock.sendall(msg.encode())
        logging.debug(msg)

