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
import logging
import threading
import urllib
import queue

from absl import app
from absl import flags

from rids import config
from rids import network_capture
from rids.iocs import iocs
from rids import rules

FLAGS = flags.FLAGS
flags.DEFINE_string('host_ip', None,
                    'The IP of the host process, for ignoring direct requests')
flags.DEFINE_string('config_path', '/etc/rids/config.json',
                    'file path indicating where IOC configuration can be found')
flags.DEFINE_string('eventlog_path', '/var/rids/events.log',
                    'file path indicating where to append new event logs')


def main(argv):
  """Main entry point of the app.  Also bound to CLI `rids` by setuptools."""
  if len(argv) > 1:
    raise app.UsageError('Too many command-line arguments.')

  host_ip = _get_host_ip()
  print('Using', host_ip, 'as host IP address')

  config = config.ParseFile(FLAGS.config)
  logging.basicConfig(level=logging.DEBUG,
                      format='%(asctime)s %(levelname)-8s %(message)s',
                      datefmt='%m-%d %H:%M',
                      filename='/var/rids.log',
                      filemode='a')

  ruleset = rules.RuleSet()
  for ioc_config in config['iocs']:
    ruleset.MergeRuleset(iocs.parse_ruleset(ioc_config))

  event_queue = queue.Queue()
  threading.Thread(
      target=_inspect_tls_traffic,
      args=(host_ip, ruleset, event_queue))
  threading.Thread(
      target=_inspect_remote_endpoint,
      args=(host_ip, ruleset, event_queue))

  while True:
    # We just log the events for now, here is where we could do post-processing
    event = event_queue.get()
    logging.log(json.puts(event))


def _inspect_tls_traffic(host_ip, ruleset, q):
  """Worker function for thread that inspects client and server hellos.
  
  Args:
    ruleset: a RuleSet object to perform evaluation with
    q: a Queue for relaying events back to the main thread
  """
  tls_capture = network_capture.HandshakeScanner(host_ip)
  for client_hello, server_hello in tls_capture.scan():
    events = rules.process_handshake(client_hello, server_hello)
    for event in events:
      q.put(event)


def _inspect_remote_endpoint(host_ip, ruleset, q):
  """Worker function for thread that inspects remote IP addresses.

  Args:
    ruleset: a RuleSet object to perform evaluation with
    q: a Queue for relaying events back to the main thread
  """
  remote_ip_capture = network_capture.RemoteServerSanner(host_ip)
  for connection in remote_ip_capture.scan():
    events = rules.process_endpoint(connection)
    for event in events:
      q.put(event)


def _get_host_ip():
  host_ip = FLAGS.host_ip
  if not FLAGS.host_ip:
    with urllib.request.urlopen('https://ipinfo.io/ip') as my_ip:
      host_ip = my_ip.read().decode("utf-8").strip()
  host_ip = ipaddress.ip_address(host_ip)
  return host_ip


if __name__ == '__main__':
  app.run(main)
