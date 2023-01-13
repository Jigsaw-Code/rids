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
Tests for the network_capture library.
"""


import io
import pytest

from rids import observations
from rids import rules
from rids.iocs import bad_ip_list


@pytest.fixture()
def bad_ips_ruleset():
  parser = bad_ip_list.FeedParser({'name': 'TEST', 'url': 'test'})
  ruleset = rules.RuleSet()
  parser.ParseRules(io.BytesIO(b"""
# comments are ok
1.1.1.1
100.12.34.56"""), ruleset)
  return ruleset


def test_good_ip_address(bad_ips_ruleset):
  ip_packet = observations.IpPacket(
    timestamp='Jan 10 13:37:42 EST 2023',
    ip_address='3.5.7.9')
  detected_events = bad_ips_ruleset.match_ip(ip_packet)
  assert not detected_events


def test_bad_ip_address(bad_ips_ruleset):
  ip_packet = observations.IpPacket(
    timestamp='Jan 10 13:37:68 EST 2023',
    ip_address='100.12.34.56')
  detected_events = bad_ips_ruleset.match_ip(ip_packet)
  assert detected_events
