#!/usr/bin/python

import logging
import signal
import threading

from ebpf_modules import ebpf_modules, Controller
from settings import modules
from time import sleep


controller = Controller()

def signal_handler(signum, frame):
    """ Send a message to all ebpf modules to stop """
    controller.stopped = True


for m in modules:
    threads = []
    logging.basicConfig(level=logging.INFO)

    if m.get('type') in ebpf_modules:
        c = ebpf_modules[m['type']](m)
        logging.info('starting \'%s\' module' % m['type'])

        thread = threading.Thread(target=c.run, args=(controller, ))
        thread.start()
        threads.append(thread)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # wait for Ctrl+C
    while 1:
        sleep(1)
        if controller.stopped:
            break

    logging.info('stopping all threads')
    for t in threads:
        t.join()

    logging.info('done')
