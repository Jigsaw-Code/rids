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

"""Tests for IP address rules creation and matching."""

from datetime import datetime
import ipaddress
import pytest

from rids.monitors import ip_monitor
from rids.rules.ip_matcher import IpMatcher
from rids.rules.ip_matcher import IpRule


@pytest.fixture()
def ip_matcher() -> IpMatcher:
  ip_matcher = IpMatcher()
  ip_matcher.add_ip_rule(IpRule(
    msg='test',
    name='TEST',
    url=None,
    fetched=datetime.now(),
    matches_ip=ipaddress.ip_address('1.1.1.1')
  ))
  ip_matcher.add_ip_rule(IpRule(
    msg='test',
    name='TEST',
    url=None,
    fetched=datetime.now(),
    matches_ip=ipaddress.ip_address('100.12.34.56')
  ))
  return ip_matcher


def test_good_ip_address(ip_matcher):
  ip_packet = ip_monitor.IpPacket(
    timestamp='Jan 10 13:37:42 EST 2023',
    ip_address='3.5.7.9')
  detected_events = ip_matcher.match_ip(ip_packet)
  assert not detected_events


def test_bad_ip_address(ip_matcher):
  ip_packet = ip_monitor.IpPacket(
    timestamp='Jan 10 13:37:68 EST 2023',
    ip_address='100.12.34.56')
  detected_events = ip_matcher.match_ip(ip_packet)
  assert detected_events
