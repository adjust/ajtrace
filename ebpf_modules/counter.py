import logging
import time

from bcc import BPF
from random import randint
from settings import config


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

        # Compile and load eBPF program to kernel
        b = BPF(text=prog)
        for f in funcs:
            b.attach_uprobe(name=config.get("executable"),
                            sym=f,
                            fn_name="%s_on_enter" % f)

        while (True):
            count = b.get_table("count")

            for k, v in count.iteritems():
                msg = 'postgres.{} {} {}\n'.format(
                        funcs[k.value],
                        v.value,
                        int(time.time()))
                logging.debug(msg)
                storage.send(msg)

            count.clear()
            time.sleep(1)

            if controller.stopped:
                break

