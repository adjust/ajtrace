import logging
import time

from bcc import BPF
from random import randint

import os,sys,inspect
currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir) 

from settings import GlobalConfig as config


class EbpfCounters:
    def __init__(self, module_config):
        self.validate(module_config)
        self.module_config = module_config

    def validate(self, module_config):
        if not module_config.get('funcs'):
            raise 'No funcs specified'

    def create_program(self):
        funcs = self.module_config.get("funcs")

        base_prog = """
            #include <uapi/linux/ptrace.h>

            BPF_ARRAY(count, u64, %d);

            static int on_enter(int idx, struct pt_regs *ctx)
            {
                u64 *hits;
                u64 zero = 0;

                hits = count.lookup_or_init(&idx, &zero);
                (*hits)++;

                return 0;
            }
            """ % len(funcs)

        func_handler = """
            int %s_on_enter(struct pt_regs *ctx)
            {
                return on_enter(%s, ctx);
            }
            """

        prog = base_prog + \
            '\n'.join([func_handler % (f, idx) for idx, f in enumerate(funcs)])

        logging.debug(prog)

        return prog

    def run(self, storage, controller):
        prog = self.create_program()
        funcs = self.module_config.get("funcs")

        try:
            # Compile and load eBPF program to kernel
            b = BPF(text=prog)
            for f in funcs:
                b.attach_uprobe(name=config.get("executable"),
                                sym=f,
                                fn_name="%s_on_enter" % f)

            while (True):
                count = b.get_table("count")
                ts = time.time()

                for k, v in count.iteritems():
                    storage.store(funcs[k.value], v.value, ts)

                count.clear()
                time.sleep(1)

                if controller.stopped:
                    break
        except Exception as e:
            # stop all other threads
            controller.stopped = True
            raise e

