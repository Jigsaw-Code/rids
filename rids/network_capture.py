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


import ipaddress
import subprocess

from rids import observations


class IpPacketMonitor:
  """Continuously scans the network traffic for remote IPs being contacted.
  The scan() function is an iterator that produces a dict{...} representing
  the endpoints (specifically the `remote_ip` and `remote_port` fields).  This
  scanning will continue until the pipe from the underlying network scanning
  process is closed.
  """
  def __init__(self, host_ip):
    self._host_ip = host_ip

  def monitor(self):
    """Generator for observations of remote IP addresses."""
    proc = _start_tshark([
        '-f', f'ip and src ip == {self._host_ip}',
        '-Tfields',
        # The order of the following fields determines the ordering in output
        '-e', 'frame.time',
        '-e', 'ip.dst',
        '-l',
    ])

    for line in iter(proc.stdout.readline, b''):
      values = line.split('\t')
      ip_info = observations.IpPacket(
        timestamp=values[0],
        remote_ip=ipaddress.ip_address(values[1]))
      yield ip_info


class TlsConnectionMonitor:
  """Continuously scans the network traffic for TLS handshakes.
  The scan() function is an iterator that produces a tuple of
    (client_hello, server_hello)
  where server_hello may be `None` if only the client hello has been seen, and
  will include both when the server_hello is found.  Each is a dict that has
  `remote_ip`, `remote_port`, `sni` (if present), `ja3`, `ja3s` as properties.
  """
  def __init__(self, host_ip):
    self._tls_streams = {}
    self._host_ip = host_ip

  def monitor(self):
    """Generator for observations of unusual TLS traffic."""
    proc = _start_tshark([
        '-f', 'tcp and not (src port 443 or dst port 443)',
        '-Y', (f'(tls.handshake.type == 1 and ip.src == {self._host_ip})' +
               f'or (tls.handshake.type == 2 and ip.dst == {self._host_ip})'),
        '-Tfields',
        # Ordering of the following fields determines the ordering in output,
        # except that missing fields are skipped.
        '-e', 'frame.time',
        '-e', 'tcp.stream',
        '-e', 'tls.handshake.type',
        '-e', 'ip.src',
        '-e', 'tcp.srcport',
        '-e', 'ip.dst',
        '-e', 'tcp.dstport',
        '-e', 'tls.handshake.extensions_server_name',
        '-e', 'tls.handshake.ja3',
        '-e', 'tls.handshake.ja3_full',
        '-e', 'tls.handshake.ja3s',
        '-e', 'tls.handshake.ja3s_full',
        '-l',
    ])

    for line in iter(proc.stdout.readline, b''):
      values = line.split('\t')
      stream_id = int(values[1])
      if int(values[2]) == 1:  # client hello
        tls_info = observations.TlsConnection(
            timestamp=values[0],
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


def _start_tshark(args):
  process = subprocess.Popen(
      ['tshark'] + args,
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE,
      universal_newlines=True)
  return process