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


from rids.event import Event
from rids.monitors import tls_monitor


class TlsMatcher:
  """Index over TLS-related rules to match against."""

  def __init__(self):
    self.allowed_sni_port = {}

  def add_allowed_sni(self, allowed_sni, expected_port) -> None:
    """Add a single TLS connection-based rule to this rule set."""
    self.allowed_tls_name_port.add(
        (allowed_sni, expected_port))

  def match_tls(self, tls_connection: tls_monitor.TlsConnection) -> Event:
    """Process observations of TLS client/server hellos.
    
    Returns:
      list of Event detials, or an empty list if nothing matches.
    """
    sni_and_port = (tls_connection.server_name, tls_connection.remote_port)
    if sni_and_port in self.allowed_sni_port:
      return []

    event = Event({
        'timestamp': tls_connection.timestamp,
        'remote_ip': tls_connection.remote_ip,
        'remote_port': tls_connection.remote_port,
        'server_name': tls_connection.server_name,
        'ja3': tls_connection.ja3,
        'ja3_full': tls_connection.ja3_full,
        'ja3s': tls_connection.ja3s,
        'ja3s_full': tls_connection.ja3s_full, 
    })
    return [event]

