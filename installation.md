`nano /etc/systemd/system/gt_stats.service`
```
[Unit]
Description=gt_stats
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/var/lib/gt-stats
ExecStart=/usr/bin/python3 /var/lib/gt-stats/gt_stats.py
Restart=always

[Install]
WantedBy=multi-user.target
```

`systemctl enable gt_stats`
`systemctl daemon-reload`
`systemctl start gt_stats` 
`systemctl status gt_stats` 
