import logging
import socket
from collections.abc import Generator
from dataclasses import dataclass

import psutil
import wmi  # type: ignore[import-untyped]

logger = logging.getLogger(__name__)


@dataclass
class Interface:
    name: str
    metric: int
    if_index: int
    ipv4: str
    ipv4_netmask: str | None

    def __lt__(self, other: "Interface") -> bool:
        return self.metric < other.metric


def get_interfaces() -> Generator[Interface]:
    c = wmi.WMI()
    adapters: dict[str, tuple[int, int]] = {}
    for adapter in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
        for addr in adapter.IPAddress:
            adapters[addr] = (adapter.IPConnectionMetric, adapter.InterfaceIndex)
    all_interfaces = psutil.net_if_addrs()
    all_stats = psutil.net_if_stats()
    for name, addrs in all_interfaces.items():
        if name not in all_stats or not all_stats[name].isup:
            continue
        for addr in addrs:
            if addr.family == socket.AF_INET:
                if addr.address != "127.0.0.1":
                    metric, if_index = adapters[addr.address]
                    yield Interface(
                        name=name,
                        metric=metric,
                        if_index=if_index,
                        ipv4=addr.address,
                        ipv4_netmask=addr.netmask,
                    )
                break
