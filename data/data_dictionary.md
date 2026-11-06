# Data Dictionary

Filled in on Days 3 and 4.

| Field | Type | Description | Source |
|---|---|---|---|
| session_id | string | Identifier of the attack or benign run | collection_log.csv |
| window_start | datetime | Start of the 60 s window | Splunk |
| src_ip | string | Source IP (excluded from features) | Splunk |
| label | string | benign, port_scan, ssh_bruteforce, ftp_bruteforce, http_bruteforce | collection_log.csv |
