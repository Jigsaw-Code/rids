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
import logging


allowed_sni_port = set([
    ('mtalk.google.com', 5228),
    ('proxy-safebrowsing.googleapis.com', 80),
    ('courier.push.apple.com', 5223),
    ('imap.gmail.com', 993),
])


def detect_tls_events(input_stream):
    unusual_tls_traffic = {}  # map[int]dict stream_id -> connection_details

    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%m-%d %H:%M',
                        filename='/var/maldetector.log',
                        filemode='a')

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
