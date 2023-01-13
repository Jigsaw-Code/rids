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
from rids import observations


@pytest.fixture()
def ruleset():
  ruleset = rules.RuleSet()
  # ... could add some default rules here
  return ruleset


def test_add_rules(ruleset):
  r1 = rules.IpRule(
    msg='test msg',
    name='test name',
    url='test url',
    fetched='fetched when?',
    matches_ip=ipaddress.ip_address('1.2.3.4'))
  ruleset.add_ip_rule(r1)
  ruleset.add_ip_rule(rules.IpRule(
    msg='test msg',
    name='test name',
    url='test url',
    fetched='fetched later.',
    matches_ip=ipaddress.ip_address('5.6.7.8')))


def _make_ip_rule(ip_address):
  return rules.IpRule(
    msg='test msg',
    name='test name',
    url='test url',
    fetched='test fetched time',
    matches_ip=ipaddress.ip_address(ip_address))


def test_match_ip(ruleset):
  ruleset.add_ip_rule(_make_ip_rule('2.2.2.2'))
  ruleset.add_ip_rule(_make_ip_rule('3.2.2.255'))
  events = ruleset.match_ip(observations.IpPacket(
    timestamp='...',
    ip_address=ipaddress.ip_address('2.2.2.2')))
  assert len(events) == 1
  assert events[0].properties['remote_ip'] == ipaddress.ip_address('2.2.2.2')