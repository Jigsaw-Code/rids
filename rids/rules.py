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


class RuleSet:
    __slots__ = ('ip_address_rules', )

    def __init__(self):
      self.ip_address_rules = collections.defaultdict(list)

    def MergeRuleset(self, other):
      """Simple implementation of a merging of rule sets."""
      for key, value in other.ip_address_rules.items():
        self.ip_address_rules[key].extend(value)

    def AddRule(self, rule):
      """Simple implementation of adding a single rule to this rule set."""
      if hasattr(rule, 'matches_ip'):
        self.ip_address_rules[str(rule.matches_ip)].append(rule)

    def ProcessHandshake(self, observation):
      """Process a handshake-related observation."""
      return Event(observation)

    def ProcessEndpoint(self, observation):
      """Process observations related to a remote IP address."""
      ip_str = str(observation['remote_ip'])
      events = []
      if ip_str in self.ip_address_rules:
        for rule in self.ip_address_rules[ip_str]:
          event = {}
          event.update(observation)
          event.update(rule.as_dict())
          events.append(event)
      return events


class Rule:
  """Represents a single rule that accommodates a variety of IOC rule types."""
  __slots__ = ('msg', 'source', 'fetched', 'matches_ip')
  # TODO: include source rule properties like 'reference', 'header', 'options'

  def __init__(self, **properties):
    for key, value in properties.items():
      setattr(self, key, value)

  def __str__(self):
    output = [
        f'{self.msg}',
        f'Found in [{self.source}] last fetched at {self.fetched}',
    ]
    
    if hasattr(self, 'reference'):
      output.append(self.reference)
    return '\n'.join(output)

  def as_dict(self):
    """Returns full definition of the rule as a string."""
    return {
        key: getattr(self, key) 
        for key in self.__slots__
        if hasattr(self, key)
    }


class Event:
  """Generalization of an Event sighting, i.e. suspicious activity or threat."""

  def __init__(self, properties):
    # The event properties have a very loose definition at this moment.
    # TODO stabilize the schema, perhaps based on MISP or Dovecot event types.
    self.properties = properties

  def __str__(self):
    return str(self.properties)
