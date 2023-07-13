pathfinder-probe
================

Set up as a systemd service:

```
$ cat /etc/systemd/system/pathfinder-probe.service
[Unit]
Description=Pathfinder-Probe
Wants=network-online.target
After=network-online.target
[Service]
Type=simple
User=pathfinder
Group=pathfinder
ExecReload=/bin/killall pathfinder-probe
Environment="RUST_LOG=info"
ExecStart=/var/lib/pathfinder/pathfinder-probe \
0.0.0.0:19999 \
https://alpha-mainnet.starknet.io \
http://127.0.0.1:9545 \
5
SyslogIdentifier=pathfinder-probe
Restart=always
[Install]
WantedBy=multi-user.target
```

```
sudo systemctl daemon-reload
sudo systemctl enable pathfinder-probe
sudo systemctl start pathfinder-probe
journalctl -u pathfinder-probe -b
```
