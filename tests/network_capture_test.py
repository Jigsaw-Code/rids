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

from rids import network_capture


@pytest.fixture()
def badips_map():
  return {
    '1.1.1.1': 'Source A',
    '4.5.6.7': 'Best IOCs',
    '100.12.34.56': 'Threatbusters',
  }

class MockLogging:
  logged = False
  def info(*args):
    logged = True


def test_good_ip_is_ok(badips_map):
  detected = network_capture.detect_bad_ips('0\t127.0.0.1\t1.2.3.4', badips_map)
  assert not detected


def test_bad_ip_is_logged(badips_map):
  detected = network_capture.detect_bad_ips('1\t4.5.6.7\t127.0.0.1', badips_map)
  assert detected
