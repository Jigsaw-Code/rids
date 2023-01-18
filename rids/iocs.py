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


import collections
from dataclasses import dataclass
from types import Set

from rids.ioc_formats import allowed_sni_port
from rids.ioc_formats import bad_ip_list
from rids.rules.ruleset import RuleSet


_IOC_PARSERS = {
  "BAD_IP_LIST": bad_ip_list.BadIpAddresses,
  "ALLOWED_SNI_PORT": allowed_sni_port.AllowedEndpoints,
}


def fetch_iocs(rids_config):
  """Parses the IOC indicated by `ioc_config` into a RuleSet instance.
  
  Args:
    rids_config: dict{'ioc_sources': list[
            dict{
              'format': str,
              ...other properties, format-dependent
            }]}

  Returns:
    RuleSet representing all IOCs in the config.
  """
  ioc_sources = rids_config.get('ioc_sources', None)
  ruleset = RuleSet()
  if not ioc_sources:
    return ruleset

  for ioc_config in ioc_sources:
    format = ioc_config.get('format', None)
    if not format:
      raise ValueError(
        f'Expected a "format" specifier for ioc_sources config: {ioc_config}')

    if format not in _IOC_PARSERS:
      raise ValueError('Unrecognized IOC feed format "{format}"')

    ioc_source = _IOC_PARSERS[format](ioc_config)
    ioc_source.provide_rules(ruleset)

  return ruleset

