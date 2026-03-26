"""
parser.py — reads log lines and turns them into LogEntry objects.

One LogEntry class. Four parser classes (one per log format).
One detect_format() function. One parse_file() function.
"""

import re
from datetime import datetime


# ── LogEntry ──────────────────────────────────────────────────────────────────
# Every parsed log line becomes a LogEntry, regardless of which format it came from.
# This means display.py and cli.py only ever need to deal with one kind of object.

class LogEntry:
    def __init__(self, timestamp, level, source, message, raw, anomaly=None):
        self.timestamp = timestamp  # datetime object, or None if it couldn't be parsed
        self.level     = level      # 'ERROR', 'WARN', 'INFO', or 'DEBUG'
        self.source    = source     # where it came from: IP address or process name
        self.message   = message    # short readable summary of the line
        self.raw       = raw        # the original unmodified log line
        self.anomaly   = anomaly    # None, or a string describing what went wrong


# ── nginx access log ──────────────────────────────────────────────────────────
# nginx combined format:
#   10.0.0.1 - - [10/Mar/2024:14:23:15 +0000] "GET /api HTTP/1.1" 200 4321 "-" "curl"

class NginxParser:

    def parse(self, line):
        line = line.strip()

        # match the five parts that are important: ip, time, request, status, bytes
        match = re.match(
            r'(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d{3}) (\S+)',
            line
        )
        if not match:
            return None

        ip       = match.group(1)
        time_str = match.group(2)
        request  = match.group(3)
        status   = int(match.group(4))
        size     = match.group(5)

        # set level and anomaly based on the HTTP status code
        if status >= 500:
            level   = 'ERROR'
            anomaly = '5xx error'
        elif status >= 400:
            level   = 'WARN'
            anomaly = None
        else:
            level   = 'INFO'
            anomaly = None

        # parse the timestamp string into a datetime object
        try:
            timestamp = datetime.strptime(time_str, '%d/%b/%Y:%H:%M:%S %z')
        except ValueError:
            timestamp = None

        # build a short message: "GET /api -> 200  (4321 bytes)"
        parts   = request.split()
        method  = parts[0] if len(parts) > 0 else ''
        path    = parts[1] if len(parts) > 1 else ''
        message = '{} {} -> {}  ({} bytes)'.format(method, path, status, size)

        return LogEntry(timestamp, level, ip, message, line, anomaly)


# ── syslog / /var/log/messages ────────────────────────────────────────────────
# syslog format:
#   Mar 10 14:23:15 web01 kernel: Out of memory: Kill process 3821

class SyslogParser:

    def parse(self, line):
        line = line.strip()

        # capture: timestamp, hostname (ignored), process name, message
        match = re.match(
            r'([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+([^:\[]+)(?:\[\d+\])?:\s+(.*)',
            line
        )
        if not match:
            return None

        time_str = match.group(1).strip()
        process  = match.group(2).strip()
        message  = match.group(3).strip()

        # search the message text for known dangerous patterns
        anomaly = None
        if re.search(r'out of memory|oom.kill|oom-killer', message, re.I):
            anomaly = 'OOM kill'
        elif re.search(r'segfault|kernel panic|SIGSEGV|core dumped', message, re.I):
            anomaly = 'segfault'
        elif re.search(r'no space left|disk full', message, re.I):
            anomaly = 'disk full'
        elif re.search(r'marked as crashed|table.*corrupt', message, re.I):
            anomaly = 'crashed table'

        level = 'ERROR' if anomaly else 'INFO'

        # syslog timestamps don't include a year, so we add the current year
        try:
            year      = datetime.now().year
            timestamp = datetime.strptime('{} {}'.format(year, time_str), '%Y %b %d %H:%M:%S')
        except ValueError:
            timestamp = None

        return LogEntry(timestamp, level, process, message, line, anomaly)


# ── MySQL / MariaDB error log ─────────────────────────────────────────────────
# MySQL 8.x:  2024-03-10T14:23:15.123456Z 0 [ERROR] [MY-012592] [InnoDB] message
# MySQL 5.7:  2024-03-10 14:23:15 12345 [ERROR] message

class MySQLErrorParser:

    def parse(self, line):
        line = line.strip()

        # try MySQL 8.x format first (has a T and Z in the timestamp)
        match = re.match(
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)\s+\d+\s+\[(\w+)\].*?\[(\w+)\]\s+(.*)',
            line
        )
        if match:
            time_str  = match.group(1)
            level     = match.group(2).upper()
            source    = match.group(3)
            message   = match.group(4)
            try:
                timestamp = datetime.strptime(time_str, '%Y-%m-%dT%H:%M:%S.%fZ')
            except ValueError:
                timestamp = None
        else:
            # try MySQL 5.7 / MariaDB format (space instead of T in timestamp)
            match = re.match(
                r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+\d+\s+\[(\w+)\]\s+(.*)',
                line
            )
            if not match:
                return None
            time_str  = match.group(1)
            level     = match.group(2).upper()
            source    = 'mysqld'
            message   = match.group(3)
            try:
                timestamp = datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S')
            except ValueError:
                timestamp = None

        # MySQL uses 'Note' and 'Warning' - normalise to INFO and WARN
        if level == 'NOTE':
            level = 'INFO'
        elif level == 'WARNING':
            level = 'WARN'

        # check the message for known MySQL problems
        anomaly = None
        if re.search(r'marked as crashed|table.*corrupt|innodb.*corrupt', message, re.I):
            anomaly = 'crashed table'
        elif re.search(r'no space left|os error 28|errcode: 28', message, re.I):
            anomaly = 'disk full'
        elif re.search(r'slave.*error|replication.*stopped|got fatal error', message, re.I):
            anomaly = 'replication error'

        return LogEntry(timestamp, level, source, message, line, anomaly)


# ── supervisord log ───────────────────────────────────────────────────────────
# supervisord format:
#   2024-03-10 14:23:15,123 INFO  success: nginx entered RUNNING state

class SupervisordParser:

    def parse(self, line):
        line = line.strip()

        match = re.match(
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d+)\s+(\w+)\s+(.*)',
            line
        )
        if not match:
            return None

        time_str = match.group(1)
        level    = match.group(2).upper()
        message  = match.group(3)

        # supervisord uses non-standard level names — normalise them
        if level in ('CRIT', 'ERRO'):
            level = 'ERROR'
        elif level == 'DEBG':
            level = 'DEBUG'

        # flag any entry that indicates a process stopped or failed
        anomaly = None
        if re.search(r'stopped:|exited:|gave up|FATAL|not expected', message, re.I):
            anomaly = 'service stopped'
        elif level == 'ERROR':
            anomaly = 'service stopped'

        try:
            timestamp = datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S,%f')
        except ValueError:
            timestamp = None

        return LogEntry(timestamp, level, 'supervisord', message, line, anomaly)


# ── format detection ──────────────────────────────────────────────────────────
# First we try to guess from the filename.
# If that does not work, we look at the first few lines of the file.

def detect_format(filepath, lines):
    name = filepath.lower()

    if 'nginx' in name or 'access' in name:
        return 'nginx'
    if 'mysqld' in name or 'mysql' in name or 'mariadb' in name:
        return 'mysql'
    if 'supervisor' in name:
        return 'supervisord'
    if 'syslog' in name or 'messages' in name:
        return 'syslog'

    # filename did not tell us — check the first 10 non-blank lines
    for line in lines[:10]:
        line = line.strip()
        if not line:
            continue
        if re.match(r'\S+ \S+ \S+ \[', line):
            return 'nginx'
        if re.match(r'[A-Za-z]{3}\s+\d+ \d{2}:\d{2}:\d{2}', line):
            return 'syslog'
        if re.match(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', line):
            return 'mysql'
        if re.match(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+', line):
            return 'supervisord'

    return 'syslog'  # fallback if nothing matched


# ── parser registry ───────────────────────────────────────────────────────────
# A dictionary so cli.py can look up the right parser by name.

PARSERS = {
    'nginx':       NginxParser(),
    'syslog':      SyslogParser(),
    'mysql':       MySQLErrorParser(),
    'supervisord': SupervisordParser(),
}


# ── parse_file ────────────────────────────────────────────────────────────────
# This is the function everything else calls.
# Open the file, detect the format, run each line through the right parser,
# and return the list of LogEntry objects plus the format name.

def parse_file(filepath, fmt='auto'):
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        lines = f.readlines()

    if fmt == 'auto':
        fmt = detect_format(filepath, lines)

    parser = PARSERS.get(fmt)
    if parser is None:
        raise ValueError("Unknown format '{}'. Choose from: {} or 'auto'".format(fmt, list(PARSERS.keys())))

    entries = []
    for line in lines:
        if not line.strip():
            continue                 # skip blank lines
        entry = parser.parse(line)
        if entry is not None:
            entries.append(entry)

    return entries, fmt
