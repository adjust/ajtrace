from .counter import EbpfCounters
from .latency import EbpfLatency
from .controller import Controller

ebpf_modules = {
    'counters': EbpfCounters,
    'latency': EbpfLatency
}
