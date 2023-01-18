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


class Event:
  """Generalization of an Event sighting, i.e. suspicious activity or threat."""

  def __init__(self, properties):
    # The event properties have a very loose definition at this moment.
    # TODO stabilize the schema, perhaps based on MISP or Dovecot event types.
    self.properties = properties

  def __str__(self):
    return str(self.properties)
