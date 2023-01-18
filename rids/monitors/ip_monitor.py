# Copyright 2022 Jigsaw Operations LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""IP monitoring classes and functionality.

IpPacketMonitor for obtaining remote IPs.
IpPacket as the type for communicating to related rules.
IpRule for representing the IOCs that packets should be checked against.
"""

from dataclasses import dataclass
import datetime
import ipaddress
from types import Generator
from types import Union

from rids.monitors import tshark


# union type for IPv4 and IPv6
IpAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


@dataclass
class IpPacket:
  """Represents a remote IP endpoint and when it was seen."""
  timestamp: str  # TODO: if calculating duration with this, make it a datetime
  ip_address: IpAddress


class IpPacketMonitor:
  """Continuously monitors the network traffic for remote IPs being contacted.

  The monitor() function is an iterator that produces a dict{...} representing
  the endpoints (specifically the `remote_ip` field and the packet's timestamp).
  """

  def __init__(self, host_ip: IpAddress):
    self._host_ip = host_ip

  def monitor(self) -> Generator[IpPacket]:
    """Generator for observations of remote IP addresses.

    The monitor is a blocking operation due to how process output is produced.
    """
    tshark_process = tshark.start_process(
        capture_filter=f'ip and src ip == {self._host_ip}',
        output_format='fields',
        fields=['frame.time', 'ip.dst'])

    for line in iter(tshark_process.stdout.readline, b''):
      values = line.strip().split('\t')
      ip_info = IpPacket(
        timestamp=values[0],
        remote_ip=ipaddress.ip_address(values[1]))
      yield ip_info

