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

from rids import network_capture
from rids.iocs import iocs

FLAGS = flags.FLAGS
flags.DEFINE_string('host_ip', None,
                    'The IP of the host process, for ignoring direct requests')
flags.DEFINE_string('config_path', '/etc/rids/config.json',
                    'file path indicating where IOC configuration can be found')
flags.DEFINE_string('eventlog_path', None,
                    'file path indicating where to append new event logs')


def main(argv):
  """Main entry point of the app.  Also bound to CLI `rids` by setuptools."""
  if len(argv) > 1:
    raise app.UsageError('Too many command-line arguments.')

  if FLAGS.eventlog_path:
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%m-%d %H:%M',
                        filename=FLAGS.eventlog_path,
                        filemode='a')

  config = _load_config()
  ruleset = iocs.fetch_iocs(config)

  host_ip = _get_host_ip()
  print(f'Using {host_ip} as host IP address')

  event_queue = queue.Queue()
  threading.Thread(
      target=_inspect_tls_traffic,
      args=(host_ip, ruleset, event_queue))
  threading.Thread(
      target=_inspect_remote_endpoints,
      args=(host_ip, ruleset, event_queue))

  while True:
    # We just log the suspicious events for now, but here is where we could
    # do post-processing and/or share sightings of known / unknown threats.
    event = event_queue.get()
    logging.log(json.puts(event))
    event_queue.task_done()


def _inspect_tls_traffic(host_ip, ruleset, q):
  """Worker function for thread that inspects client and server hellos.
  
  Args:
    ruleset: a RuleSet object to perform evaluation with
    q: a Queue for relaying events back to the main thread
  """
  tls_connection = network_capture.TlsConnectionMonitor(host_ip)
  for tls_info in tls_connection.monitor():
    events = ruleset.match_tls(tls_info)
    for event in events:
      q.put(event)


def _inspect_remote_endpoints(host_ip, ruleset, q):
  """Worker function for thread that inspects remote IP addresses.

  Args:
    ruleset: a RuleSet object to perform evaluation with
    q: a Queue for relaying events back to the main thread
  """
  remote_ip = network_capture.RemoteServerScanner(host_ip)
  for ip_info in remote_ip.monitor():
    events = ruleset.match_ip(ip_info)
    for event in events:
      q.put(event)


def _get_host_ip():
  """Retrieves the host IP address from its flag, else from a remote site.
  
  Returns:
    ipaddress of the host running RIDS
  """
  host_ip = FLAGS.host_ip
  if not FLAGS.host_ip:
    with urllib.request.urlopen('https://ipinfo.io/ip') as my_ip:
      host_ip = my_ip.read().decode("utf-8").strip()
  host_ip = ipaddress.ip_address(host_ip)
  return host_ip


def _load_config():
  config = {}
  if FLAGS.config_path:
    with open(FLAGS.config_path) as f:
      config = json.load(f)
  return config


if __name__ == '__main__':
  app.run(main)