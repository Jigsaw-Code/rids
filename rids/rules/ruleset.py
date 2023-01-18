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

from dataclasses import dataclass

from rids.rules import ip_matcher
from rids.rules import tls_matcher


@dataclass
class RuleSet:
  ip_matcher : ip_matcher.IpMatcher = ip_matcher.IpMatcher()
  tls_matcher : tls_matcher.TlsMatcher = tls_matcher.TlsMatcher()

