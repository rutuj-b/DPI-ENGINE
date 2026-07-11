"""The DPI engine: a Reader → LoadBalancer → FastPath → Writer pipeline.

Packets are consistently hashed at each stage so every packet in a flow is
handled by the same fast-path worker, keeping per-flow state coherent.
"""

from __future__ import annotations

import queue
import threading
from dataclasses import dataclass, field

from .flow import Flow, classify
from .parser import parse
from .pcap import Packet, PcapReader, PcapWriter
from .rules import RuleManager
from .stats import EngineStats
from .tuples import PROTO_TCP, PROTO_UDP, FiveTuple, tuple_hash

# Sentinel pushed through the queues to signal end-of-stream.
_STOP = object()

QUEUE_MAX = 10000


@dataclass
class EngineConfig:
    """Pipeline sizing: ``num_load_balancers`` LBs, each feeding ``fps_per_lb`` workers."""

    num_load_balancers: int = 2
    fps_per_lb: int = 2

    @property
    def total_fps(self) -> int:
        return self.num_load_balancers * self.fps_per_lb


@dataclass
class PacketJob:
    """A packet in flight through the pipeline."""

    ts_sec: int
    ts_usec: int
    tuple: FiveTuple
    data: bytes
    payload_offset: int
    payload_length: int

    def payload(self) -> bytes:
        return self.data[self.payload_offset : self.payload_offset + self.payload_length]


@dataclass
class EngineResult:
    """Everything reported after a capture is processed."""

    stats: dict
    lb_dispatched: list[int] = field(default_factory=list)
    fp_processed: list[int] = field(default_factory=list)


class FastPath:
    """A worker that classifies flows, applies rules and forwards packets."""

    def __init__(
        self,
        fp_id: int,
        rules: RuleManager,
        stats: EngineStats,
        output_queue: "queue.Queue",
    ):
        self.fp_id = fp_id
        self._rules = rules
        self._stats = stats
        self._output = output_queue
        self.input: "queue.Queue" = queue.Queue(QUEUE_MAX)
        self.processed = 0
        self._flows: dict[FiveTuple, Flow] = {}
        self._thread = threading.Thread(target=self._run, name=f"FP{fp_id}")

    def start(self) -> None:
        self._thread.start()

    def join(self) -> None:
        self._thread.join()

    def _run(self) -> None:
        while True:
            job = self.input.get()
            if job is _STOP:
                self._output.put(_STOP)
                return
            self.processed += 1
            self._process(job)

    def _process(self, job: PacketJob) -> None:
        flow = self._flows.get(job.tuple)
        if flow is None:
            flow = Flow(tuple=job.tuple)
            self._flows[job.tuple] = flow
        flow.packets += 1
        flow.byte_count += len(job.data)

        if not flow.classified:
            classify(flow, job.payload())

        if not flow.blocked:
            reason = self._rules.should_block(
                job.tuple.src_ip, job.tuple.dst_port, flow.app_type, flow.sni
            )
            flow.blocked = reason is not None

        self._stats.record_app(flow.app_type, flow.sni)

        if flow.blocked:
            self._stats.record_dropped()
        else:
            self._stats.record_forwarded()
            self._output.put(job)


class LoadBalancer:
    """Distributes packets across a pool of fast-path workers by flow hash."""

    def __init__(self, lb_id: int, fast_paths: list[FastPath]):
        self.lb_id = lb_id
        self._fps = fast_paths
        self._num_fps = len(fast_paths)
        self.input: "queue.Queue" = queue.Queue(QUEUE_MAX)
        self.dispatched = 0
        self._thread = threading.Thread(target=self._run, name=f"LB{lb_id}")

    def start(self) -> None:
        self._thread.start()

    def join(self) -> None:
        self._thread.join()

    def _run(self) -> None:
        while True:
            job = self.input.get()
            if job is _STOP:
                for fp in self._fps:
                    fp.input.put(_STOP)
                return
            fp_index = tuple_hash(job.tuple) % self._num_fps
            self._fps[fp_index].input.put(job)
            self.dispatched += 1


class DPIEngine:
    """Top-level orchestrator that wires the pipeline and runs a capture."""

    def __init__(
        self,
        config: EngineConfig | None = None,
        rules: RuleManager | None = None,
    ):
        self.config = config or EngineConfig()
        self.rules = rules or RuleManager()
        self.stats = EngineStats()

        self._output: "queue.Queue" = queue.Queue(QUEUE_MAX)
        self._fps: list[FastPath] = [
            FastPath(i, self.rules, self.stats, self._output)
            for i in range(self.config.total_fps)
        ]
        # Partition the workers across load balancers, matching the pipeline
        # topology: LB *n* owns a contiguous block of ``fps_per_lb`` workers.
        self._lbs: list[LoadBalancer] = []
        for lb_id in range(self.config.num_load_balancers):
            start = lb_id * self.config.fps_per_lb
            block = self._fps[start : start + self.config.fps_per_lb]
            self._lbs.append(LoadBalancer(lb_id, block))

    def process(self, input_path: str, output_path: str) -> EngineResult:
        """Filter ``input_path`` into ``output_path`` and return statistics."""
        with PcapReader(input_path) as reader:
            assert reader.header is not None
            writer = PcapWriter(output_path, reader.header)
            writer_thread = threading.Thread(
                target=self._writer_loop, args=(writer,), name="Writer"
            )

            for fp in self._fps:
                fp.start()
            for lb in self._lbs:
                lb.start()
            writer_thread.start()

            self._read_and_dispatch(reader)

            # Drain the pipeline: one sentinel per LB cascades to the workers,
            # each of which forwards a sentinel to the writer.
            for lb in self._lbs:
                lb.input.put(_STOP)
            for lb in self._lbs:
                lb.join()
            for fp in self._fps:
                fp.join()
            writer_thread.join()
            writer.close()

        return EngineResult(
            stats=self.stats.snapshot(),
            lb_dispatched=[lb.dispatched for lb in self._lbs],
            fp_processed=[fp.processed for fp in self._fps],
        )

    def _read_and_dispatch(self, reader: PcapReader) -> None:
        num_lbs = len(self._lbs)
        for packet in reader:
            parsed = parse(packet.data)
            if parsed is None or not parsed.has_ip:
                continue
            if not parsed.has_tcp and not parsed.has_udp:
                continue

            job = PacketJob(
                ts_sec=packet.ts_sec,
                ts_usec=packet.ts_usec,
                tuple=parsed.five_tuple(),
                data=packet.data,
                payload_offset=parsed.payload_offset,
                payload_length=parsed.payload_length,
            )
            self.stats.record_packet(
                len(packet.data), parsed.has_tcp, parsed.has_udp
            )
            lb_index = tuple_hash(job.tuple) % num_lbs
            self._lbs[lb_index].input.put(job)

    def _writer_loop(self, writer: PcapWriter) -> None:
        remaining = len(self._fps)
        while remaining > 0:
            item = self._output.get()
            if item is _STOP:
                remaining -= 1
                continue
            writer.write_packet(
                Packet(
                    ts_sec=item.ts_sec,
                    ts_usec=item.ts_usec,
                    orig_len=len(item.data),
                    data=item.data,
                )
            )
