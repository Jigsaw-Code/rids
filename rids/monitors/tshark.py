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


import subprocess


def start_process(
    capture_filter: str = None,
    display_filter: str = None,
    fields: list[str] = [],
    output_format: str = 'fields',
    flush_every_packet: bool = True) -> subprocess.Popen:
  """Starts tshark as a Popen process and pipes its stdout and stderr.
  
  For more on filter formats, see:
    > man pcap-filter
        https://www.tcpdump.org/manpages/pcap-filter.7.html
    > man wireshark-filter
        https://www.wireshark.org/docs/man-pages/wireshark-filter.html

  Args:
    capture filter: pcap-style filter rule for packets to monitor
    display filter: additional filters to apply (wireshark-filter format)
    fields: list of field names as defined by wireshark
    output_format: how to format the packet data being output
    flush_every_packet: whether tshark should flush instead of buffering output
  """
  if not len(fields):
    raise ValueError("Must pass at least one field to tshark")

  command = ['tshark']
  if capture_filter:
    command.extend(['-f', capture_filter])
  if display_filter:
    command.extend(['-Y', display_filter])
  command.extend(['-T', output_format])
  for field in fields:
    command.extend(['-e', field])
  if flush_every_packet:
    command.append('-l')

  return subprocess.Popen(
      command,
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE,
      universal_newlines=True)
