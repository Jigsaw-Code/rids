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

import collections
import datetime
from dataclasses import dataclass
import ipaddress
from typing import Union

from rids.event import Event
from rids.monitors import ip_monitor

IpAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


@dataclass
class IpRule:
  """Represents a single rule that accommodates a variety of IOC rule types."""

  msg: str
  name: str
  url: str 
  fetched: datetime.datetime
  matches_ip: IpAddress
  reference: str = None

  def __str__(self):
    output = [
        f'[{self.matches_ip}] {self.msg}',
        f'Found in [{self.name}] last fetched at {self.fetched}',
    ]
    
    if self.reference:
      output.append(self.reference)
    return '\n'.join(output)  


class IpMatcher:
  """Index over IP address rules, compatible with both IPv4 and IPv6."""

  def __init__(self):
    self.ip_address_rules = collections.defaultdict(list)

  def add_ip_rule(self, ip_rule: IpRule) -> None:
    """Add a single IP-based rule to this rule set."""
    self.ip_address_rules[str(ip_rule.matches_ip)].append(ip_rule)

  def match_ip(self, ip_packet: ip_monitor.IpPacket) -> Event:
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

