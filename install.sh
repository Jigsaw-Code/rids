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


# PIP doesn't like installing as root; check user and switch if needed
if [[ $EUID -eq 0 ]]; then
  RIDS_USER="${RIDS_USER:-rids}"

  echo "PIP will not install as root; run as ${RIDS_USER}? (y/n) "
  read ANSWER
  ANSWER=$(echo "${ANSWER}" | tr '[:upper:]' '[:lower:]')
  if [[ $ANSWER == "y" ]]; then
    # check for existing user
    if [[ $(id "${RIDS_USER}" >/dev/null; echo $?) -ne 0 ]]; then
      echo "There is no user called ${RIDS_USER}; create one? (y/n)"
      read ANSWER
      ANSWER=$(echo "${ANSWER}" | tr '[:upper:]' '[:lower:]')
      if [[ $ANSWER == "y" ]]; then
        sudo useradd -s /bin/bash -m -G adm,sudo,dip,plugdev,www-data $RIDS_USER
        # system should prompt user for password, otherwise add `chpasswd` call here
        SUDO_COMMAND="sudo -u ${RIDS_USER}"
      else
        echo "cannot install RIDS as root; aborting."
        exit 1
      fi
    fi

    # install RIDS from repo, including its python dependencies
    ${SUDO_COMMAND} pip3 install --upgrade git+https://github.com/Jigsaw-Code/rids.git@main

  else
    echo "cannot install RIDS as root; specify RIDS_USER env-var for the user to install as."
    echo "aborting."
    exit 1
  fi
fi

RIDS_INSTALL_PATH="$(python3 -m pip show rids | grep Location | cut -d" " -f 2)"

# this may be an upgrade, stop the service if it exists and is running
systemctl stop rids.service >& /dev/null

# Define sysctl .service config for /etc/systemd and start service
cp "${RIDS_INSTALL_PATH}/rids.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable rids.service --now
