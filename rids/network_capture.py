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


class RemoteServerScanner:
  """Continuously scans the network traffic for remote IPs being contacted.
  The scan() function is an iterator that produces a dict{...} representing
  the endpoints (specifically the `remote_ip` and `remote_port` fields).  This
  scanning will continue until the pipe from the underlying network scanning
  process is closed.
  """
  def __init__(self, host_ip):
    self._proc = _start_tshark([
        '-f', 'ip and src ip == {host_ip}',
        '-Tfields',
        # The order of the following fields determines the ordering in output
        '-e', 'frame.time',
        '-e', 'ip.dst',
        '-l',
    ])

  def scan(self):
    """Generator for observations of remote IP addresses."""
    for line in iter(self._proc.stdout.readline, b''):
      values = line.split('\t')
      observation = {
        'timestamp': values[0],
        'remote_ip': values[1],
      }
      yield observation


class HandshakeScanner:
  """Continuously scans the network traffic for TLS handshakes.
  The scan() function is an iterator that produces a tuple of
    (client_hello, server_hello)
  where server_hello may be `None` if only the client hello has been seen, and
  will include both when the server_hello is found.  Each is a dict that has
  `remote_ip`, `remote_port`, `sni` (if present), `ja3`, `ja3s` as properties.
  """
  def __init__(self, host_ip):
    self._proc = _start_tshark([
        '-f', 'tcp and not (src port 443 or dst port 443)',
        '-Y', (f'(tls.handshake.type == 1 and ip.src == {host_ip})' +
              f'or (tls.handshake.type == 2 and ip.dst == {host_ip})'),
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
    self._tls_streams = {}

  # Ignore these false positives.
  # TODO: include these in handshake-related rules instead of filtering here?
  _allowed_sni_port = set([
      ('mtalk.google.com', 5228),
      ('proxy-safebrowsing.googleapis.com', 80),
      ('courier.push.apple.com', 5223),
      ('imap.gmail.com', 993),
  ])

  def scan(self):
    """Generator for observations of unusual TLS traffic."""
    for line in iter(self._proc.stdout.readline, b''):
      values = line.split('\t')
      observation = {
        'timestamp': values[0],
      }
      stream_id = int(values[1])
      if int(values[2]) == 1:  # client hello
        sni_and_port = (values[7], int(values[6]))
        if sni_and_port in self._allowed_sni_port:
          continue

        observation['remote_ip'] = ipaddress.ip_address(values[5])
        observation['remote_port'] = int(values[6])
        observation['server_name'] = values[7]
        observation['ja3'] = values[8]
        observation['ja3_full'] = values[9]
        self._tls_streams[stream_id] = observation

      elif int(values[2]) == 2:  # server hello
        observation = self._tls_streams.get(stream_id, None)
        if not observation:
          continue
        observation['ja3s'] = values[8]
        observation['ja3s_full'] = values[9]
        yield observation
        del self._tls_streams[stream_id]


def _start_tshark(args):
  process = subprocess.Popen(
      ['tshark'] + args,
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE,
      universal_newlines=True)
  return process