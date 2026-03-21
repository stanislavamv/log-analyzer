# log-analyzer

CLI tool for parsing and filtering Linux log files — built
from two years of production log analysis across enterprise clusters.

Parses nginx access logs, syslog, MySQL error logs, and supervisord
output into interactive terminal tables with column sorting, filtering,
and anomaly detection.

## Why this exists

Diagnosing production incidents from raw log files is slow.
You end up doing this manually:
    grep "ERROR" /var/log/app.log | awk '{print $3, $5}' | sort | uniq -c
...across 4 different log formats, across multiple servers.
This tool handles the parsing and rendering so you can focus on reading.

## Install

    pip install -r requirements.txt

## Usage

    python main.py --file /var/log/nginx/access.log --format nginx
    python main.py --file /var/log/syslog --filter ERROR --sort time
    python main.py --file app.log --format json  # pipe-able output

## What it detects automatically

- 5xx HTTP errors (nginx)
- OOM kill events (syslog/dmesg)
- MySQL crashed table entries (mysqld.err)
- Supervisor process restarts (supervisord.log)

## Built with

- Python 3.10+
- rich (terminal rendering)
- argparse (CLI interface)

## Background

Built while working production support and SRE for enterprise network monitoring
infrastructure. Every support session involved manually parsing 3-4 log
formats to find the root cause of an incident. This tool standardizes
that process.
