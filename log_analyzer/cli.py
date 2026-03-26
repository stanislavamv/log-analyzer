"""
cli.py - defines the command-line flags and runs the tool.

Three functions:
  filter_entries() - applies --level, --search, --anomalies filters
  build_parser()   - defines every flag with argparse
  main()           - ties it all together: parse -> filter -> display
"""

import argparse
import sys

from log_analyzer.parser  import parse_file, PARSERS
from log_analyzer.display import print_summary, print_table, output_json, console


def filter_entries(entries, level=None, search=None, anomalies_only=False):
    """Return only the entries that pass every active filter."""
    result = []
    for e in entries:
        # skip if --level was given and this entry is a different level
        if level and e.level.upper() != level.upper():
            continue
        # skip if --search was given and the text is not in this entry
        if search:
            needle = search.lower()
            if needle not in e.message.lower() and needle not in e.raw.lower():
                continue
        # skip if --anomalies was given and this entry has no anomaly
        if anomalies_only and e.anomaly is None:
            continue
        result.append(e)
    return result


def build_parser():
    """Define all the command-line flags."""
    p = argparse.ArgumentParser(
        prog='log-analyzer',
        description='Parse and analyse Linux log files.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python main.py tests/sample_nginx.log
  python main.py tests/sample_syslog.log --anomalies
  python main.py tests/sample_mysql.log --level ERROR
  python main.py tests/sample_nginx.log --search "POST /login"
  python main.py tests/sample_syslog.log --out json
""",
    )

    p.add_argument('file',
        help='Path to the log file to analyse.')

    p.add_argument('--format', '-f',
        choices=list(PARSERS.keys()) + ['auto'],
        default='auto',
        help='Log format. Options: nginx, syslog, mysql, supervisord, auto  (default: auto)')

    p.add_argument('--level', '-l',
        metavar='LEVEL',
        help='Only show entries at this level: ERROR, WARN, INFO')

    p.add_argument('--search', '-s',
        metavar='TEXT',
        help='Only show entries whose message or raw line contains TEXT')

    p.add_argument('--anomalies', '-a',
        action='store_true',
        help='Only show entries where an anomaly was detected')

    p.add_argument('--tail', '-t',
        type=int,
        metavar='N',
        help='Only look at the last N lines of the file')

    p.add_argument('--raw', '-r',
        action='store_true',
        help='Show the original log line instead of the parsed summary')

    p.add_argument('--out',
        choices=['table', 'json'],
        default='table',
        help='Output format: table (default) or json')

    p.add_argument('--no-summary',
        action='store_true',
        help='Skip the summary header at the top')

    return p


def main():
    args = build_parser().parse_args()

    # step 1: read and parse the log file
    try:
        entries, fmt = parse_file(args.file, args.format)
    except FileNotFoundError:
        console.print('[bold red]error:[/bold red] file not found — {}'.format(args.file))
        sys.exit(1)
    except ValueError as e:
        console.print('[bold red]error:[/bold red] {}'.format(e))
        sys.exit(1)

    # step 2: if --tail was given, keep only the last N entries
    if args.tail:
        entries = entries[-args.tail:]

    # step 3: apply any filters the user asked for
    entries = filter_entries(
        entries,
        level=args.level,
        search=args.search,
        anomalies_only=args.anomalies,
    )

    # step 4: if nothing matched the filters, say so and exit
    if not entries:
        console.print('[yellow]No entries matched your filters.[/yellow]')
        sys.exit(0)

    # step 5: print the output in the requested format
    if args.out == 'json':
        output_json(entries)
    else:
        if not args.no_summary:
            print_summary(entries, fmt, args.file)
        print_table(entries, show_raw=args.raw)
