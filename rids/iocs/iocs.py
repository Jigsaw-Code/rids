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


_PARSERS = {
  "BAD_IP_LIST": bad_ip_list.FeedParser,
}


def fetch_and_parse_ruleset(ioc_config):
  """Parses the IOC indicated by `ioc_config` into a RuleSet instance.
  
  Args:
    ioc_config: dict{'name', 'url', 'format'}
  """
  format = ioc_config['format']
  if format not in _PARSERS:
    raise ValueError('Unrecognized IOC feed format |{format}|')
  
  parser = _PARSERS[format](ioc_config)
  return parser.Parse(_fetch_contents(ioc_config['url']), ioc_config['name'])


def _fetch_contents(fullurl):
  """Fetch the data contents (encoded as utf-8) for the resource found at `url`.
  
  Args:
    fullurl: string to URL where the IOC feed data is found.
  """
  with urllib.request.urlopen()