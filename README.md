# qipu-monitor

Outside monitoring of www.qipu.org: `site_monitor.py` runs on GitHub's runners every 10 minutes
(`.github/workflows/monitor.yml`), checks the site's pages, data, assistant, alert links, tiles,
DNS and certificates, and pushes changes to a phone through ntfy. Every token is a secret of this
repository. The source and the setup notes live in the site's repository (`ops/monitor/`); this
repository is a copy made by its `publish.sh`.
