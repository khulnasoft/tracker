Integrating with [Prometheus](https://prometheus.io)

!!! Performance Attention
    Current Prometheus integration targets performance numbers for event
    production, consumption and detection. It does not target the detections
    themselves.

Tracker is enabled for prometheus scraping by default. Scraping can be done
through the following URLs:

**tracker** can be scraped through `:3366/metrics`

> Metrics addresses can be changed through **tracker** command line
> arguments `metrics` and `listen-addr`, check `--help` for more information.

!!! Tip
    Check [this tutorial] for more information as well.

[this tutorial]: ../../tutorials/deploy-grafana-dashboard.md
