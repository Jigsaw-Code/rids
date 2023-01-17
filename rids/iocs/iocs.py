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

"""Combined IOC feed parser interface for the different formats of IOCs."""


import collections
from dataclasses import dataclass
from types import Set

from rids.iocs import allowed_sni_port
from rids.iocs import bad_ip_list
from rids.monitors.ip_monitor import IpRule
from rids.monitors.tls_monitor import TlsRule


_IOC_PARSERS = {
  "BAD_IP_LIST": bad_ip_list.BadIpAddresses,
  "ALLOWED_SNI_PORT": allowed_sni_port.AllowedEndpoints,
}


def fetch_iocs(rids_config):
  """Parses the IOC indicated by `ioc_config` into a RuleSet instance.
  
  Args:
    rids_config: { 'iocs': list[dict{'name', 'url', 'format'}] }

  Returns:
    RuleSet representing all IOCs in the config.
  """
  ioc_sources = rids_config.get('ioc_sources', None)
  ruleset = RuleSet()
  if not ioc_sources:
    return ruleset

  for ioc_config in ioc_sources:
    format = ioc_config['format']
    if format not in _IOC_PARSERS:
      raise ValueError('Unrecognized IOC feed format "{format}"')

    ioc_source = _IOC_PARSERS[format](ioc_config)
    ioc_source.provide_rules(ruleset)

  return ruleset


@dataclass
class RuleSet:
  ip_address_rules = collections.defaultdict(list)
  allowed_tls_name_port : Set[tuple[str, int]] = set()

  def add_ip_rule(self, ip_rule: IpRule):
    """Add a single IP-based rule to this rule set."""
    self.ip_address_rules[str(ip_rule.matches_ip)].append(ip_rule)

  def add_tls_rule(self, tls_rule: TlsRule):
    """Add a single TLS connection-based rule to this rule set."""
    if tls_rule.allowed_sni:
      self.allowed_tls_name_port.add(
        (tls_rule.allowed_sni, tls_rule.expected_port))

  def match_ip(self, ip_packet):
    """Process observations related to a remote IP address."""
    ip_str = str(ip_packet.ip_address)
    events = []
    if ip_str in self.ip_address_rules:
      for rule in self.ip_address_rules[ip_str]:
        event = Event({
            'timestamp': ip_packet.timestamp,
            'remote_ip': ip_packet.ip_address,
            'msg': rule.msg,
            'name': rule.name,
            'url': rule.url,
            'fetched': rule.fetched,
            'reference': rule.reference,
        })
        events.append(event)
    return events

  def match_tls(self, tls_connection):
    """Process a TLS-handshake related observation."""
    sni_and_port = (tls_connection.server_name, tls_connection.remote_port)
    if sni_and_port in self.allowed_tls_name_port:
      return []
    event = Event({
        'timestamp': tls_connection.timestamp,
        'remote_ip': tls_connection.remote_ip,
        'remote_port': tls_connection.remote_port,
        'server_name': tls_connection.server_name,
        'ja3': tls_connection.ja3,
        'ja3_full': tls_connection.ja3_full,
        'ja3s': tls_connection.ja3s,
        'ja3s_full': tls_connection.ja3s_full, 
    })
    return [event]


class Event:
  """Generalization of an Event sighting, i.e. suspicious activity or threat."""

  def __init__(self, properties):
    # The event properties have a very loose definition at this moment.
    # TODO stabilize the schema, perhaps based on MISP or Dovecot event types.
    self.properties = properties

  def __str__(self):
    return str(self.properties)
