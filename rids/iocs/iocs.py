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

"""Combined IOC feed parser interface for the different formats of IOCs."""


import urllib.request

from rids.iocs import bad_ip_list
from rids import rules


_PARSERS = {
  "BAD_IP_LIST": bad_ip_list.FeedParser,
}


def fetch_iocs(rids_config):
  """Parses the IOC indicated by `ioc_config` into a RuleSet instance.
  
  Args:
    rids_config: { 'iocs': list[dict{'name', 'url', 'format'}] }

  Returns:
    RuleSet representing all IOCs in the config.
  """
  ioc_config = rids_config.get('iocs', None)
  if not ioc_config:
    return rules.RuleSet()

  ruleset = rules.RuleSet()
  for ioc in ioc_config:
    format = ioc['format']
    if format not in _PARSERS:
      raise ValueError('Unrecognized IOC feed format |{format}|')

    parser = _PARSERS[format](ioc_config)
    with urllib.request.urlopen(ioc_config['url']) as ioc_data:
      parser.ParseRules(ioc_data, ruleset)