# RIDS: Remote Intrusion Detection System

This tool allows you to inspect some types of unusual activity on your network in order to detect malware installed on endpoints.


## Installing

These instructions assume a VPS running on Digital Ocean, but should
apply to other deployment environments, perhaps with slight changes.

Open an SSH connection or enter a console with sudo'er permissions and execute
the following:

    curl https://raw.githubusercontent.com/Jigsaw-Code/rids/master/install.sh | sudo bash


## About

You can use this tool to set up tshark on a VPS for detecting
suspicious activity.  In this case that means TLS handshakes that are on a
non-standard port and/or missing an SNI.  This definition may expand as 
features are added to RIDS.

`tshark` is a command-line version of wireshark that provides a useful view of network activity for a device.  Installing this tool will add entries to the system journal for later review.  This project may evolve to surface this information to server clients more conveniently, but at present it requires a root user access to the server.

This service can also be configured to look for known-compromised IP addresses, based on
publicly-available IOC sources or a custom list of IP addresses.  See config_example.json
for an example config that pulls from EmergingThreats compromised IP list.  The expected
format is newline-separated string-encoded addresses, one on each line.

To pass different configurations you can use the --config_path flag when running RIDS (or in the
detect.sh script that launches it), with the path being relative to the working directory where
the Python script is being run.


## Viewing logs output

Because the service is running on systemd, the script's output can be viewed using `journalctl`:

    journalctl -u detection.service --follow

There are additional flags for checking the logs from a specific boot session, during a time window, and for converting timestamps into a local time zone.  See this Digital Ocean doc about journalctl for more details.

By default, tshark buffers its output so it may be up to a few minutes between an event and when it shows up in journalctl logs.  You can make tshark immediately flush to stdout after every line by passing -l ("ell") with its other options in the shell script where it is started, and then restart the service.  Typically, this won't be necessary, but could be useful while debugging any modifications to the tshark arguments.

At first you may not see anything other than the beginning output of tshark -- it checks for updates then prints a couple lines "... [Main MESSAGE] -- Capture started." and "File: /tmp/wireshark_eth0…pcapng".  Any additional output will be from the TLS secure handshake going to an unusual port.  There will be a timestamp and some details about the source and host including a server name if one is provided, then the client and server fingerprints of the secure handshake.  These can be used for later analysis.


## Caveats

In general you should not see any TLS activity, in non standard ports, with a few exceptions:

   * DNS-over-TLS on port 853
   * proxy-safebrowsing.googleapis.com:80
   * mtalk.google.com:5228
   * courier.push.apple.com:5223
   * imap.gmail.com:993

Also see:

   * [Apple ports](https://support.apple.com/en-us/HT202944)
   * [GMail ports](https://support.google.com/mail/answer/7126229?hl=en#zippy=%2Cstep-change-smtp-other-settings-in-your-email-client)
   * [Android ports](https://support.google.com/work/android/answer/10513641?hl=en)
   * [Firebase ports](https://firebase.google.com/docs/cloud-messaging/concept-options#messaging-ports-and-your-firewall)
   * [Google IPs](https://cloud.google.com/vpc/docs/configure-private-google-access#ip-addr-defaults)

The `sni_filter.py` script filters out these client and server hellos based on the SNI.  If you see other SNIs that you would rather ignore in the output, they can be added to the allow-list in that script.

