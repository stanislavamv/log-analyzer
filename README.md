# log-analyzer

CLI tool for parsing and filtering Linux log files in a colour-coded
terminal table. Handles nginx access logs, syslog, MySQL error logs,
and supervisord - all with the same interface and automatic anomaly detection.

## Why this exists

Diagnosing production incidents from raw log files is slow.
You end up running the same grep-awk-sort sequence across
four different formats on different servers. This tool normalises
them into one view so you can focus on reading the data instead of
reshaping it.

Built from three years of working production Linux incidents -
OOM kills, MySQL crashed tables, replication failures, 5xx storms,
and process crashes - where a tool like this would have saved
20 minutes per incident.

## What it detects automatically

| Format       | Detected anomalies                                        |
|--------------|-----------------------------------------------------------|
| nginx        | 5xx errors (500, 502, 503, 504)                           |
| syslog       | OOM kills, segfaults, disk full (errno 28), crashed tables|
| MySQL error  | Crashed tables, disk full, replication errors             |
| supervisord  | Service stops, FATAL state, spawn errors                  |

## Install

Python 3.10+ required.

```
pip install rich
```

## Usage

```
python main.py <logfile> [options]
```

Auto-detects format from filename. Override with `--format`.

### Examples

```bash
# Parse an nginx access log
python main.py /var/log/nginx/access.log

# Show only anomalies from a syslog file
python main.py /var/log/syslog --anomalies

# Show only ERROR level from a MySQL error log
python main.py /var/log/mysql/mysqld.err --format mysql --level ERROR

# Look for failed login attempts
python main.py access.log --search "401" --tail 500

# Machine-readable JSON output for scripting
python main.py mysqld.err --anomalies --out json

# Force format, show raw lines instead of parsed summary
python main.py app.log --format syslog --raw --no-summary
```

## All flags

| Flag               | Short | Description                                              |
|--------------------|-------|----------------------------------------------------------|
| `--format FORMAT`  | `-f`  | `nginx`, `syslog`, `mysql`, `supervisord`, `auto`        |
| `--level LEVEL`    | `-l`  | Filter to: `ERROR`, `WARN`, `INFO`                       |
| `--search TEXT`    | `-s`  | Show only entries containing TEXT in message or source   |
| `--anomalies`      | `-a`  | Show only entries with a detected anomaly                |
| `--tail N`         | `-t`  | Only analyse the last N lines of the file                |
| `--raw`            | `-r`  | Show original log line instead of parsed message         |
| `--out FORMAT`     |       | `table` (default) or `json`                              |
| `--no-summary`     |       | Skip the header block                                    |

## Format auto-detection

`--format auto` (the default) detects the log format by:
1. Filename - `nginx` or `access` → nginx, `mysqld` or `mysql` → mysql, etc.
2. Content - the first 20 non-blank lines are checked against regex patterns.

Pass `--format` explicitly if the filename is generic (e.g. `app.log`).

## Project structure

```
log_analyzer/
├── parser.py    # LogEntry dataclass + one parser class per format
├── display.py   # rich terminal rendering and JSON output
└── cli.py       # argparse interface and filter logic
main.py          # entry point
tests/           # sample log files for each supported format
```

## Running the sample files

```bash
python main.py tests/sample_nginx.log
python main.py tests/sample_syslog.log --anomalies
python main.py tests/sample_mysql.log --level ERROR
python main.py tests/sample_supervisord.log --anomalies
```

## Adding a new log format

1. Add a new parser class in `parser.py` with a `parse(self, line)` method
   that returns a `LogEntry` or `None`.
2. Add an entry to the `PARSERS` dict at the bottom of `parser.py`.
3. Add format name detection to `detect_format()`.
4. Add a sample log file to `tests/`.

## Requirements

- Python 3.10+
- [rich](https://github.com/Textualize/rich) >= 13.0.0

## License

MIT
