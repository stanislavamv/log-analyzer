"""
display.py — takes a list of LogEntry objects and prints them.

Three functions:
  print_summary() — header block with counts and anomaly list
  print_table()   — color-coded table of entries
  output_json()   — machine-readable JSON for piping
"""

import json
from rich.console import Console
from rich.table   import Table
from rich.text    import Text
from rich         import box

from log_analyzer.parser import LogEntry

console = Console()

# what color to use for each log level in the table
LEVEL_STYLE = {
    'ERROR': 'bold red',
    'WARN':  'bold yellow',
    'INFO':  'white',
    'DEBUG': 'dim',
}


def print_summary(entries, fmt, filepath):
    """Print a stats header and list any anomalies found."""
    total     = len(entries)
    errors    = 0
    warnings  = 0
    anomalies = []

    for e in entries:
        if e.level == 'ERROR':
            errors += 1
        elif e.level == 'WARN':
            warnings += 1
        if e.anomaly is not None:
            anomalies.append(e)

    console.print()
    console.print('[dim]──[/dim] [bold]{}[/bold]'.format(filepath))
    console.print()
    console.print(
        '  [dim]parsed[/dim] [bold]{}[/bold]   '
        '[dim]format[/dim] [cyan]{}[/cyan]   '
        '[red]errors {}[/red]   '
        '[yellow]warnings {}[/yellow]   '
        '[magenta]anomalies {}[/magenta]'.format(total, fmt, errors, warnings, len(anomalies))
    )
    console.print()

    if anomalies:
        console.print('  [bold magenta]Anomalies:[/bold magenta]')
        for e in anomalies:
            if e.timestamp:
                ts = e.timestamp.strftime('%m-%d %H:%M:%S')
            else:
                ts = '—'
            if len(e.message) > 72:
                msg = e.message[:69] + '...'
            else:
                msg = e.message
            console.print('  [dim]{}[/dim]  [magenta]{:<20}[/magenta]  [dim]{}[/dim]'.format(ts, e.anomaly, msg))
        console.print()


def print_table(entries, show_raw=False, max_msg=90):
    """Render entries as a color-coded Rich table."""
    table = Table(
        box=box.SIMPLE_HEAD,
        header_style='bold white',
        border_style='dim',
        expand=True,
        padding=(0, 1),
    )

    table.add_column('#',        style='dim',     width=5,  no_wrap=True)
    table.add_column('Timestamp',                 width=20, no_wrap=True)
    table.add_column('Level',                     width=7,  no_wrap=True)
    table.add_column('Source',   style='cyan',    width=18, no_wrap=True)
    table.add_column('Message',                   ratio=1)
    table.add_column('Flag',     style='magenta', width=18)

    for i, e in enumerate(entries, 1):
        # format the timestamp, fall back to a dash if it is None
        if e.timestamp:
            ts = e.timestamp.strftime('%m-%d %H:%M:%S')
        else:
            ts = '—'

        # show raw line or parsed message depending on --raw flag
        msg = e.raw if show_raw else e.message

        # truncate long messages
        if len(msg) > max_msg:
            msg = msg[:max_msg - 3] + '...'

        # pick a color for the message based on level
        if e.level == 'ERROR':
            msg_color = 'red'
        elif e.level == 'WARN':
            msg_color = 'yellow'
        else:
            msg_color = 'white'

        # Text() is a rich object — it's just a string with a color attached
        level_text = Text(e.level, style=LEVEL_STYLE.get(e.level, 'white'))
        msg_text   = Text(msg,     style=msg_color)

        table.add_row(
            str(i),
            ts,
            level_text,
            e.source[:18],
            msg_text,
            e.anomaly or '',
        )

    console.print(table)


def output_json(entries):
    """Print all entries as a JSON array — useful for piping to jq."""
    records = []
    for e in entries:
        if e.timestamp:
            ts = e.timestamp.isoformat()
        else:
            ts = None
        records.append({
            'timestamp': ts,
            'level':     e.level,
            'source':    e.source,
            'message':   e.message,
            'anomaly':   e.anomaly,
        })
    print(json.dumps(records, indent=2))
