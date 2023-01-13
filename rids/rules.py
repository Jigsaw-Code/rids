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
Generalizes the various formats of IOCs into Rule and RuleSet.

Rule is a value type that represents evaluation on a single rule.  RuleSet
instances represent a set of independent and overlapping Rule instances.

RuleSet should typically be constructed from one of the flavors of parsers
in `rids.iocs` or merged from combining a pair of RuleSet instances.  Its

Evaluation of the RuleSet is done with the ProcessHandshake(...) and
ProcessEndpoint(...) methods which take an observation and return a list
of zero or more Event instances with their matching rules in the RuleSet.
"""


import collections
from dataclasses import dataclass

from rids import observations


class RuleSet:
    __slots__ = ('ip_address_rules', 'allowed_sni_port') 

    def __init__(self):
      self.ip_address_rules = collections.defaultdict(list)
      # TODO this allow-list could be expressed in terms of rules from a file
      # similar to the indicators of compromise, but explicitly coded for now.
      self.allowed_sni_port = set([
          ('mtalk.google.com', 5228),
          ('proxy-safebrowsing.googleapis.com', 80),
          ('courier.push.apple.com', 5223),
          ('imap.gmail.com', 993),
      ])

    def add_ip_rule(self, ip_rule):
      """Simple implementation of adding a single rule to this rule set."""
      self.ip_address_rules[str(ip_rule.matches_ip)].append(ip_rule)

    def match_tls(self, tls_connection):
      """Process a handshake-related observation."""
      sni_and_port = (tls_connection.server_name, tls_connection.remote_port)
      if sni_and_port in self.allowed_sni_port:
        return []
      return [Event(tls_connection)]

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


@dataclass
class IpRule:
  """Represents a single rule that accommodates a variety of IOC rule types."""

  msg: str
  name: str
  url: str 
  fetched: str
  matches_ip: observations.IpType
  reference: str = None

  def __str__(self):
    output = [
        f'{self.msg}',
        f'Found in [{self.name}] last fetched at {self.fetched}',
    ]
    
    if self.reference:
      output.append(self.reference)
    return '\n'.join(output)


class Event:
  """Generalization of an Event sighting, i.e. suspicious activity or threat."""

  def __init__(self, properties):
    # The event properties have a very loose definition at this moment.
    # TODO stabilize the schema, perhaps based on MISP or Dovecot event types.
    self.properties = properties

  def __str__(self):
    return str(self.properties)
