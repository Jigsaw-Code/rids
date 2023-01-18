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

"""Tests for TLS connection rules creation and matching."""

from datetime import datetime
import ipaddress
import pytest

from rids.ioc_formats.allowed_sni_port import AllowedEndpoints
from rids.rules.ruleset import RuleSet
from rids.rules.tls_matcher import TlsMatcher
from rids.monitors.tls_monitor import TlsConnection


@pytest.fixture()
def tls_matcher() -> TlsMatcher:
  tls_matcher = TlsMatcher()
  tls_matcher.add_allowed_endpoint('example.com', 421)
  tls_matcher.add_allowed_endpoint('justchatting.com', 5223)
  return tls_matcher


def _fake_connection(server_name: str, port: int):
  tls_connection = TlsConnection(
    timestamp=str(datetime.now()),
    remote_ip=ipaddress.ip_address('101.23.45.67'),
    remote_port=port,
    server_name=server_name,
    ja3='...',
    ja3_full='...',
    ja3s='...',
    ja3s_full='...',
  )
  return tls_connection


def test_ok_tls_connection(tls_matcher):
  tls_connection = _fake_connection(server_name='justchatting.com', port=5223)
  detected_events = tls_matcher.match_tls(tls_connection)
  assert not detected_events


def test_suspicious_tls_connection(tls_matcher):
  tls_connection = _fake_connection(server_name='notevil.com', port=444)
  detected_events = tls_matcher.match_tls(tls_connection)
  assert detected_events


def test_parse_allowed_sni_config():
  config = {
      'format': 'ALLOWED_SNI_PORT',
      'name': 'recognized unusual TLS (name, port) combinations',
      'allow': [
          ['mtalk.google.com', 5228],
          ['courier.push.apple.com', 5223],
      ]
  }
  parser = AllowedEndpoints(config)
  parser.provide_rules(RuleSet())