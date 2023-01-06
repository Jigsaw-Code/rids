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
Generalizes the various formats of IOCs into a common class, RuleSet.

RuleSet is a value type that represents evaluation on packets and connections.
It can be constructed from one of the flavors of parsers in `rids.iocs` or
merged from combining a pair of RuleSet instances.  Its constructor takes a
dict (or equivalent) argument that mirrors the tree-like structure of its
combined rules, for ease of creating new IOC decoders and when testing.

Evaluation of the RuleSet is done with the process_connection(...) and
process_packet(...) which take appropriate context objects and produce a
list of zero or more Event instances for any rules in the RuleSet.
"""

from rids.event import Event


class Rule:
  __slots__ = (
      'msg',
      'source', 'reference',
               'header', 'options', 

class RuleSet:
    __slots__ = ('endpoint_pattern')