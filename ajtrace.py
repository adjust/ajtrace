#!/usr/bin/python

import logging
import signal
import threading
import time

from ebpf_modules import ebpf_modules, Controller
from settings import modules, config
from graphite import GraphiteStorage


controller = Controller()

def signal_handler(signum, frame):
    """ Send a message to all ebpf modules to stop """
    controller.stopped = True


host = config.get('graphite_host', 'localhost')
port = config.get('graphite_port', 2003)

for m in modules:
    threads = []
    logging.basicConfig(level=logging.DEBUG)

    if m.get('type') in ebpf_modules:
        c = ebpf_modules[m['type']](m)
        logging.info('starting \'%s\' module' % m['type'])

        # create a dedicated connection for each module
        storage = GraphiteStorage(host, port)
        storage.connect()

        thread = threading.Thread(target=c.run, args=(storage, controller, ))
        thread.start()
        logging.debug('thread started')
        threads.append(thread)

        # TODO: It looks like a race condition occures when two modules are
        #       installed simultaniously. Should think of a better solution.
        time.sleep(1)
    else:
        raise 'Unknown module type \'%\'' % m.get('type')

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# wait for Ctrl+C
while 1:
    time.sleep(1)
    if controller.stopped:
        break

logging.info('stopping all threads')
for t in threads:
    t.join()

logging.info('done')
