#!/bin/sh

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

# Install script for RIDS, the Remote Intrusion Detection System.

# install script
add-apt-repository --assume-yes ppa:wireshark-dev/stable
apt --assume-yes update
apt --assume-yes install tshark python3-pip

# download repo with scripts
git clone https://github.com/Jigsaw-Code/rids
pushd rids

pip3 install absl-py

# copy wrapper script into a bin/ path
cp detect.sh /usr/local/sbin
chmod +x /usr/local/sbin/detect.sh
cp packet_filter.py /usr/local/sbin
cp rids.py /usr/local/sbin

# Define sysctl .service config to /etc/systemd and start service

# first, stop the service if it exists and is running
systemctl stop rids_detection.service >& /dev/null

cp rids_detection.service /etc/systemd/system/
systemctl daemon-reload
systemctl start rids_detection.service
systemctl enable rids_detection.service

# return to previous directory
popd
