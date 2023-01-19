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

# use the dev/stable version of tshark to get ja3/ja3s signatures
add-apt-repository ppa:wireshark-dev/stable
apt --assume-yes update

# install system dependencies
apt --assume-yes install tshark python3-pip

# install RIDS from repo, including its python dependencies
pip3 install git+git://github.com/Jigsaw-Code/rids.git@main

# this may be an upgrade, stop the service if it exists and is running
systemctl stop rids.service >& /dev/null

# Define sysctl .service config for /etc/systemd and start service
cp rids.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable rids.service --now
