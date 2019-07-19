import logging
import time

from bcc import BPF
import ctypes as ct

import os,sys,inspect
currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir) 

from settings import GlobalConfig as config


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

        # check that probe_start is set
        if 'probe_start' not in module_config:
            raise '\'probe_start\' is not specified'

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

    def run(self, storage, controller):
        prog = self.create_program()
        probe_start = self.module_config['probe_start']
        probe_end = self.module_config.get('probe_end')

        try:
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
                ts = time.time()

                for k, v in stats.iteritems():
                    if v.value:
                        metric = '%s.%s' % (probe_start, pow(2, k.value))
                        storage.store(metric, v.value, ts)

                stats.clear()
                time.sleep(1)

                if controller.stopped:
                    break
        except Exception as e:
            # stop all other threads
            controller.stopped = True
            raise e

