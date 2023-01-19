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


from dataclasses import dataclass
from datetime import datetime
import ipaddress
from typing import Generator
from typing import Union

from rids.monitors import tshark

IpAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


@dataclass
class TlsConnection:
  """Represents salient properties of a TLS connection and when it was seen."""
  timestamp: datetime
  remote_ip: IpAddress
  remote_port: int
  server_name: str
  ja3: str
  ja3_full: str
  ja3s: str
  ja3s_full: str


class TlsConnectionMonitor:
  """Continuously monitors the network traffic for TLS handshakes.

  Use monitor() to generate TlsConnection instances from network traffic.
  """
  def __init__(self, host_ip: IpAddress):
    self._tls_streams = {}
    self._host_ip = host_ip

  def monitor(self) -> Generator[TlsConnection, None, None]:
    """Generator for observations of unusual TLS traffic.
    
    """
    tshark_process = tshark.start_process(
        capture_filter='tcp and not (src port 443 or dst port 443)',
        display_filter=(
          f'(tls.handshake.type == 1 and ip.src == {self._host_ip})' +
          f'or (tls.handshake.type == 2 and ip.dst == {self._host_ip})'),
        output_format='fields',
        fields=['frame.time',
                'tcp.stream',
                'tls.handshake.type',
                'ip.src',
                'tcp.srcport',
                'ip.dst',
                'tcp.dstport',
                'tls.handshake.extensions_server_name',
                'tls.handshake.ja3',
                'tls.handshake.ja3_full',
                'tls.handshake.ja3s',
                'tls.handshake.ja3s_full'])

    for line in iter(tshark_process.stdout.readline, b''):
      values = line.split('\t')
      stream_id = int(values[1])
      if int(values[2]) == 1:  # client hello
        tls_info = TlsConnection(
            timestamp=datetime.strptime(values[0], '%b %d, %Y %H:%M:%S %Z'),
            remote_ip=ipaddress.ip_address(values[5]),
            remote_port=int(values[6]),
            server_name=values[7],
            ja3=values[8],
            ja3_full=values[9])
        self._tls_streams[stream_id] = tls_info

      elif int(values[2]) == 2:  # server hello
        tls_info = self._tls_streams.get(stream_id, None)
        if not tls_info:
          continue
        tls_info.ja3s = values[8]
        tls_info.ja3s_full = values[9]
        yield tls_info
        del self._tls_streams[stream_id]
