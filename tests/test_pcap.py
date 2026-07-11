import os
import tempfile
import unittest

from dpi_engine.pcap import Packet, PcapReader, PcapWriter, PcapError, GlobalHeader


class PcapRoundTripTests(unittest.TestCase):
    def _header(self) -> GlobalHeader:
        return GlobalHeader(
            magic_number=0xA1B2C3D4,
            version_major=2,
            version_minor=4,
            thiszone=0,
            sigfigs=0,
            snaplen=65535,
            network=1,
            endian="<",
        )

    def test_write_then_read(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "cap.pcap")
            with PcapWriter(path, self._header()) as writer:
                writer.write_packet(Packet(1, 2, 4, b"data"))
                writer.write_packet(Packet(3, 4, 5, b"hello"))

            with PcapReader(path) as reader:
                packets = list(reader)
            self.assertEqual(len(packets), 2)
            self.assertEqual(packets[0].data, b"data")
            self.assertEqual(packets[1].data, b"hello")
            self.assertEqual(packets[1].ts_sec, 3)

    def test_invalid_magic_raises(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "bad.pcap")
            with open(path, "wb") as f:
                f.write(b"\x00" * 24)
            with self.assertRaises(PcapError):
                PcapReader(path)


if __name__ == "__main__":
    unittest.main()
