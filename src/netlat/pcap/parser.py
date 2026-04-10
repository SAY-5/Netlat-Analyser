"""Protocol definition for packet parsers."""

from __future__ import annotations

from typing import Iterator, Protocol, runtime_checkable

from netlat.flows.models import CaptureMetadata, Packet


@runtime_checkable
class PacketParser(Protocol):
    """Protocol that all pcap parser backends must implement."""

    def parse_pcap(self, path: str) -> Iterator[Packet]:
        """Parse a pcap/pcapng file and yield Packet objects.

        Args:
            path: File system path to the pcap file.

        Yields:
            Parsed Packet objects.
        """
        ...

    def parse_pcap_with_metadata(self, path: str) -> tuple[list[Packet], CaptureMetadata]:
        """Parse a pcap file and return packets with capture metadata.

        Args:
            path: File system path to the pcap file.

        Returns:
            Tuple of (list of packets, capture metadata).
        """
        ...
