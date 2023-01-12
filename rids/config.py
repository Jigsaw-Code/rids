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
Configuration parsing and validataion.

The config format may change, certainly its contents will.  This is where
type-checking and consistency checks go.
"""

import json


def parse_file(file_path):
  """Parse the configuration defined at the indicated path."""
  # TODO validation checks on config values, schema isn't yet defined
  with open(file_path) as f:
    return json.load(f)


def parse_string(config_str):
  """Parse a configuration from a utf8 str-like representation."""
  # TODO: validation checks in common with file-based parsing.
  # Simple implementation for now.
  return json.loads(f)
