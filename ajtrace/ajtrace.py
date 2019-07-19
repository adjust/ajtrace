#!/usr/bin/python

import argparse
import logging
import signal
import threading
import time

from ebpf_modules import ebpf_modules, Controller
from settings import GlobalConfig as config
from graphite import GraphiteBackend


controller = Controller()

def signal_handler(signum, frame):
    """ Send a message to all ebpf modules to stop """
    controller.stopped = True

def setup_logging():
    log_level = config.get('log_level', 'info')
    log_file = config.get('log_file')

    level = {
        'debug': logging.DEBUG,
        'info': logging.INFO,
        'warning': logging.WARNING,
        'error': logging.ERROR,
        'critical': logging.CRITICAL
    }.get(log_level.lower())

    if not level:
        raise 'Unknow log level \'%s\'' % log_level.lower()

    logging.basicConfig(filename=log_file, level=level)

def main(config_file):
    config.initialize(config_file)
    setup_logging()

    host = config.get('graphite_host', 'localhost')
    port = config.get('graphite_port', 2003)

    for m in config.get('modules'):
        threads = []

        if m.get('type') in ebpf_modules:
            c = ebpf_modules[m['type']](m)
            logging.info('starting \'%s\' module' % m['type'])

            # create a dedicated connection for each module
            storage = GraphiteBackend(host, port)
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


parser = argparse.ArgumentParser(description='ajtrace - eBPF base monitoring tool')
parser.add_argument('-c', '--config', default='config.yml', help='config file')
args = parser.parse_args()

main(args.config)
