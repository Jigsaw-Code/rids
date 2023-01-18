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

"""IOC parser for allowing certain unusual (server name, port) sightings."""


from rids.rules.ruleset import RuleSet
from rids.rules.tls_matcher import TlsMatcher


class AllowedEndpoints:
  """Parses allowed (sni, port) pairs directly from an ioc_sources config."""
  def __init__(self, config):
    self.name = config['name']
    self.allowlist = config['allow']

  def provide_rules(self, ruleset: RuleSet):
    """Add rules to the TlsMatcher according to the configured allowlist."""
    for server_name, port in self.allowlist:
      ruleset.tls_matcher.add_allowed_endpoint(server_name, port)