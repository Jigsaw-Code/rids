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

"""IOC feed parser for lists of compromised host IPs (newline separated)."""


from datetime import datetime
import ipaddress

from rids import rules


class FeedParser:
  """Parses newline-separated list of IP addresses into a RuleSet."""
  def __init__(self, config):
    self.source_url = config['url']
    self.source_name = config.get('name', 'UNKNOWN')
    self.msg = config.get('msg', 'contact with a potentially compromised host')

  def ParseRules(self, ioc_data, ruleset):
    timestamp = str(datetime.now())
    for line in ioc_data.readlines():
      line = line.decode('utf-8').strip()
      if not line or line[0] == '#':
        # skip empty lines and comments
        continue
      try:
        bad_ip = ipaddress.ip_address(line)
      except ValueError:
        # Do nothing with badly-formatted addresses in these files.
        continue

      rule = rules.IpRule(
          msg=self.msg,
          name=self.source_name,
          url=self.source_url,
          fetched=timestamp,
          matches_ip=bad_ip,
      )
      ruleset.add_ip_rule(rule)
