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
Tests for the RuleSet and Rules classes.
"""

import ipaddress
import pytest

from rids import rules


@pytest.fixture()
def ruleset():
  ruleset = rules.RuleSet()
  # ... could add some default rules here
  return ruleset


def test_add_rules(ruleset):
  r1 = rules.Rule(matches_ip='1.2.3.4')
  ruleset.AddRule(r1)
  ruleset.AddRule(rules.Rule(matches_ip='5.6.7.8'))


def test_merge_rules(ruleset):
  ruleset.AddRule(rules.Rule(matches_ip='2.2.2.2', msg='hello'))
  ruleset.AddRule(rules.Rule(matches_ip='3.2.2.255'))
  ruleset.AddRule(rules.Rule(matches_ip='3.3.3.3'))
  other_ruleset = rules.RuleSet()
  other_ruleset.AddRule(rules.Rule(matches_ip='2.2.2.2', msg='test'))

  assert 1 == len(ruleset.ProcessEndpoint(
      {'remote_ip': ipaddress.ip_address('2.2.2.2')}))
  ruleset.MergeRuleset(other_ruleset)
  assert 2 == len(ruleset.ProcessEndpoint(
      {'remote_ip': ipaddress.ip_address('2.2.2.2')}))


def test_process_endpoint(ruleset):
  ruleset.AddRule(rules.Rule(matches_ip='2.2.2.2', msg='hello'))
  ruleset.AddRule(rules.Rule(matches_ip='3.2.2.255'))
  events = ruleset.ProcessEndpoint(
      {'remote_ip': ipaddress.ip_address('2.2.2.2')})
  assert len(events) == 1
  assert events[0]['remote_ip'] == ipaddress.ip_address('2.2.2.2')