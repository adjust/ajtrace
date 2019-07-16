import logging
import socket
import time

from bcc import BPF
import ctypes as ct
from settings import config


units_map = {
    'us': 'MICROSECONDS',
    'ms': 'MILLISECONDS',
    's':  'SECONDS'
}

class EbpfLatency:
    def __init__(self, module_config):
        self.validate(module_config)
        self.module_config = module_config

    def validate(self, module_config):
        """ Validate input parameters and prevent malicious code injections """
        self.options = {}

        # units option
        units = module_config.get('units', 'ms')
        if units not in units_map:
            raise 'Incorrect units type: \'%\'; available values are %' \
                % (units, ', '.join(units_map.keys()))
        self.options['UNITS'] = units_map[units]

        # buckets number option
        buckets = module_config.get('buckets', 16)
        if not type(buckets) is int:
            raise 'Expected integer as buckets number, but got %s' % type(buckets)
        self.options['BUCKETS'] = buckets

    def create_program(self):
        prog = """
            #include <uapi/linux/ptrace.h>

            #define UNITS

            BPF_HISTOGRAM(stats, int, BUCKETS);
            BPF_HASH(temp, u64, u64);

            int probe_start(struct pt_regs *ctx) {
                u64 timestamp = bpf_ktime_get_ns();
                u64 pid = bpf_get_current_pid_tgid();

                temp.update(&pid, &timestamp);
                return 0;
            }

            int probe_end(struct pt_regs *ctx) {
                u64 *timestamp;
                u64 pid = bpf_get_current_pid_tgid();

                if ((timestamp = temp.lookup(&pid)) == NULL)
                    return 0;

                u64 delta = bpf_ktime_get_ns() - *timestamp;

            #if defined(MICROSECONDS)
                delta /= 1000;
            #elif defined(MILLISECONDS)
                delta /= 1000000;
            #elif defined(SECONDS)
                delta /= 1000000000;
            #endif

                stats.increment(bpf_log2l(delta));

                temp.delete(&pid);
                return 0;
            }
        """

        for k, v in self.options.items():
            prog = prog.replace(k, str(v))

        logging.debug(prog)

        return prog

    def run(self, controller):
        prog = self.create_program()
        probe_start = self.module_config['probe_start']
        probe_end = self.module_config.get('probe_end')
        host = config.get("graphite_host")
        port = config.get("graphite_port")

        # TODO: extract to a separate object
        sock = socket.socket()
        sock.connect((host, port))

        # Compile and load eBPF program to kernel
        bpf = BPF(text=prog)
        path = config.get("executable")

        bpf.attach_uprobe(name=path, sym=probe_start, fn_name='probe_start');
        if probe_start == probe_end or not probe_end:
            bpf.attach_uretprobe(name=path, sym=probe_start, fn_name='probe_end');
        else:
            bpf.attach_uprobe(name=path, sym=probe_end, fn_name='probe_end');

        while (True):
            stats = bpf.get_table("stats")

            for k, v in stats.iteritems():
                if v.value:
                    msg = 'test.{}.{} {} {}\n'.format(
                            probe_start,
                            k.value,
                            v.value,
                            int(time.time()))
                    logging.debug(msg)
                    sock.sendall(msg.encode())

            stats.clear()
            time.sleep(1)

            if controller.stopped:
                break

