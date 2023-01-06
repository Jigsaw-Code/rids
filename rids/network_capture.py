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
    for line in iter(self._proc.stdout.readline, b''):



class HandshakeScanner:
  """Continuously scans the network traffic for TLS handshakes.

  The scan() function is an iterator that produces a tuple of
    (client_hello, server_hello)
  where server_hello may be `None` if only the client hello has been seen, and
  will include both when the server_hello is found.  Each is a dict that has
  `remote_ip`, `remote_port`, `sni` (if present), `ja3`, `ja3s` as properties.
  """
  def __init__(self, host_ip):
    _start_tshark([
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

  # Ignore these false positives.
  # TODO: include these in the handshake rules instead of defining them here.
  _allowed_sni_port = set([
      ('mtalk.google.com', 5228),
      ('proxy-safebrowsing.googleapis.com', 80),
      ('courier.push.apple.com', 5223),
      ('imap.gmail.com', 993),
  ])

  def scan():
    # TODO ...yield
    pass


def _start_tshark(args):


def detect_tls_events(input_stream):
    unusual_tls_traffic = {}  # map[int]dict stream_id -> connection_details

    for line in iter(input_stream, b''):
        values = line.split('\t')
        if len(values) >= 8:
            stream_id = int(values[1])
            if int(values[2]) == 1:  # client hello
                sni_and_port = (values[7], int(values[6]))
                if sni_and_port not in allowed_sni_port:
                    unusual_tls_traffic[stream_id] = {
                        'client_ts': values[0],
                        'server_ip': values[5],
                        'server_port': values[6],
                        'server_name': values[7],
                        'ja3': values[8],
                        'ja3_full': values[9],
                    }
            elif int(values[2]) == 2:  # server hello
                port = int(values[4])
                if port == 443:
                    continue
                connection_details = unusual_tls_traffic.get(stream_id, None)
                if not connection_details:
                    continue
                connection_details['ja3s'] = values[8]
                connection_details['ja3s_full'] = values[9]
                logging.info('connection_details %s', connection_details)
                del unusual_tls_traffic[stream_id]

            print(line.rstrip())

 
def warn_about_ip_address(ip_address, bad_ips):
  ip_address = str(ip_address)
  if ip_address in bad_ips:
    ioc_sources = bad_ips[ip_address]
    logging.info('CONNECTING WITH BAD IP %s (found in %s)',
                 ip_address, ioc_sources)
    return True
  return False
 

def detect_bad_ips(dataline, bad_ips):
  if not dataline:
    return False
  values = dataline.split('\t')
  ip_from, ip_to = ipaddress.ip_address(values[1]), ipaddress.ip_address(values[2])
  if (warn_about_ip_address(ip_from, bad_ips)
      or warn_about_ip_address(ip_to, bad_ips)):
    return True
  return False
