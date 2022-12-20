#! /usr/bin/env python3

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


"""
Main entry point for RIDS, a Remote Intrusion Detection System.
"""


import ipaddress
import json
import os
import subprocess
import sys
import urllib.request

from absl import app
from absl import flags

import packet_filter

FLAGS = flags.FLAGS
flags.DEFINE_string('host_ip', None,
                    'The IP of the host process, for ignoring direct requests')
flags.DEFINE_string('config_path', 'config.json',
                    'Path where IOC configuration can be found; uses config.json by default')


def retrieve_bad_ips():
  bad_ips = {}
  with open(FLAGS.config_path, 'r') as f:
    config = json.load(f)
    for source in config['ioc_sources']:
      # Download a fresh version of each IOC source in the config.
      with urllib.request.urlopen(source['url']) as ioc_data:
        # TODO check format of ioc source, branch to different parsers
        # For now, the only source format is newline-seprated bad IPv4 addresses
        for line in ioc_data.readlines():
          line = line.strip().decode('utf-8')
          if not line: continue
          bad_ip = ipaddress.ip_address(line)
          # TODO we need to handle the possibility that an IPaddr appears in more than one list
          bad_ips[bad_ip] = source['name']
  return bad_ips


def get_external_ip():
  with urllib.request.urlopen('https://ipinfo.io/ip') as my_ip:
    return my_ip.read().decode("utf-8").strip()


def main(argv):
  if len(argv) > 1:
    raise app.UsageError('Too many command-line arguments.')

  host_ip = FLAGS.host_ip
  if not FLAGS.host_ip:
    host_ip = get_external_ip()
  host_ip = ipaddress.ip_address(host_ip)
  print('Using', host_ip, 'as host IP address')

  # Spawn tshark and read its output.  This assumes the wireshark-dev/stable
  # version of tshark has been installed.
  oddtls_capture = subprocess.Popen([
      'tshark',
      '-f', 'tcp and not (src port 443 or dst port 443)',
      '-Y', (f'(tls.handshake.type == 1 and ip.src == {host_ip})' +
             f'or (tls.handshake.type == 2 and ip.dst == {host_ip})'),
      '-Tfields',
      # The order of the following fields determines the ordering in output
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
      ],
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE,
      universal_newlines=True)
  packet_filter.detect_tls_events(oddtls_capture.stdout.readline)

  bad_ips = retrieve_bad_ips()
  ip_capture = subprocess.Popen([
      'tshark',
      '-Tfields',
      # The order of the following fields determines the ordering in output
      '-e', 'frame.time',
      '-e', 'ip.src',
      '-e', 'ip.dst',
      '-l',
      ],
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE,
      universal_newlines=True)

  # TODO define a class in packet_filter instead of using a function
  # filter = packet_filter.Filter(); filter.add_bad_ips(bad_ips); ...
  packet_filter.detect_bad_ips(ip_capture.stdout.readline, bad_ips)


if __name__ == '__main__':
  app.run(main)
