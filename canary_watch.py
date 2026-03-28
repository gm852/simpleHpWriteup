#!/usr/bin/env python3
"""
canary_watch.py — Live OpenCanary Log Monitor
Usage: python3 canary_watch.py [logfile]
Default logfile: /var/log/opencanary.log
"""

import json
import sys
import time
import os
from collections import defaultdict, deque
from datetime import datetime

try:
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.columns import Columns
    from rich import box
except ImportError:
    print("Installing rich...")
    os.system("pip3 install rich -q")
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.columns import Columns
    from rich import box

# ── Config ────────────────────────────────────────────────────────────────────
LOG_FILE    = sys.argv[1] if len(sys.argv) > 1 else "/var/log/opencanary.log"
REFRESH_HZ  = 2          # screen refreshes per second
MAX_RECENT  = 12         # recent events to show

LOGTYPE_NAMES = {
    1000: "STARTUP",
    1001: "INFO",
    2000: "FTP Login",
    3000: "HTTP GET",
    3001: "HTTP POST",
    4000: "SSH New Conn",
    4001: "SSH Banner",
    4002: "SSH Login Attempt",
    4003: "SSH Login Success",
    5000: "Telnet Login",
    6001: "SMB Login",
    9000: "MYSQL Login",
    9001: "MSSQL Login",
}

PORT_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 80: "HTTP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP",
    5900: "VNC", 8080: "HTTP-Alt",
}

# ── State ─────────────────────────────────────────────────────────────────────
class State:
    def __init__(self):
        self.passwords      = defaultdict(int)
        self.usernames      = defaultdict(int)
        self.src_ips        = defaultdict(int)
        self.port_hits      = defaultdict(int)
        self.logtype_counts = defaultdict(int)
        self.recent_events  = deque(maxlen=MAX_RECENT)
        self.total_events   = 0
        self.attack_events  = 0
        self.start_time     = datetime.now()
        self.first_hit_time = None
        self.last_event_time= None
        self.seen_lines     = 0

state = State()

# ── Log parser ─────────────────────────────────────────────────────────────────
def parse_line(line: str):
    line = line.strip()
    if not line:
        return
    try:
        e = json.loads(line)
    except json.JSONDecodeError:
        return

    lt   = e.get("logtype", -1)
    src  = e.get("src_host", "")
    port = e.get("dst_port", -1)
    ts   = e.get("local_time", "")[:19]
    ld   = e.get("logdata", {})

    state.total_events += 1
    state.logtype_counts[lt] += 1

    # Skip pure startup/info noise for attack counters
    if lt in (1000, 1001):
        return

    state.attack_events += 1
    if state.first_hit_time is None:
        state.first_hit_time = ts
    state.last_event_time = ts

    if src:
        state.src_ips[src] += 1
    if port and port > 0:
        state.port_hits[port] += 1

    # Credentials
    pwd  = ld.get("PASSWORD") or ld.get("password", "")
    user = ld.get("USERNAME") or ld.get("username", "")
    if pwd:
        state.passwords[pwd] += 1
    if user:
        state.usernames[user] += 1

    # Recent events feed
    label = LOGTYPE_NAMES.get(lt, f"type-{lt}")
    pname = PORT_NAMES.get(port, str(port) if port > 0 else "?")
    cred  = f"[dim]{user}[/dim]:[red]{pwd}[/red]" if user or pwd else ""
    state.recent_events.appendleft({
        "time":  ts[-8:],   # HH:MM:SS only
        "src":   src or "—",
        "port":  pname,
        "event": label,
        "cred":  cred,
    })

def tail_file():
    """Read new lines from log file each refresh cycle."""
    try:
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
        new_lines = lines[state.seen_lines:]
        state.seen_lines = len(lines)
        for line in new_lines:
            parse_line(line)
    except FileNotFoundError:
        pass

# ── UI builders ───────────────────────────────────────────────────────────────
def make_header() -> Panel:
    uptime = str(datetime.now() - state.start_time).split(".")[0]
    elapsed_since_first = ""
    if state.first_hit_time:
        try:
            ft = datetime.strptime(state.first_hit_time, "%Y-%m-%d %H:%M:%S")
            elapsed_since_first = f"  │  First hit +{str(datetime.now()-ft).split('.')[0]}"
        except:
            pass

    txt = Text(justify="center")
    txt.append("🍯  CANARY WATCH  🍯", style="bold bright_yellow")
    txt.append(f"   {LOG_FILE}", style="dim")
    txt.append(f"\n⏱  Uptime {uptime}", style="cyan")
    txt.append(elapsed_since_first, style="green")
    txt.append(f"   │  Refreshing every {1/REFRESH_HZ:.1f}s", style="dim")
    return Panel(txt, style="yellow", box=box.HEAVY)

def make_stats() -> Panel:
    t = Table.grid(padding=(0, 3))
    t.add_column(style="dim")
    t.add_column(style="bold white")

    unique_ips = len(state.src_ips)
    t.add_row("Total log lines",  f"[cyan]{state.total_events}[/cyan]")
    t.add_row("Attack events",    f"[red]{state.attack_events}[/red]")
    t.add_row("Unique IPs",       f"[yellow]{unique_ips}[/yellow]")
    t.add_row("Cred pairs seen",  f"[magenta]{len(state.passwords)}[/magenta]")
    t.add_row("First hit",        f"[green]{state.first_hit_time or '—'}[/green]")
    t.add_row("Last event",       f"[green]{state.last_event_time or '—'}[/green]")

    return Panel(t, title="[bold]📊 Overview[/bold]", border_style="cyan", box=box.ROUNDED)

def make_top_passwords() -> Panel:
    tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold magenta",
                expand=True)
    tbl.add_column("#", style="dim", width=4)
    tbl.add_column("Password", style="red")
    tbl.add_column("Hits", justify="right", style="bold white")

    top = sorted(state.passwords.items(), key=lambda x: x[1], reverse=True)[:10]
    for i, (pwd, cnt) in enumerate(top, 1):
        bar = "█" * min(cnt, 20)
        tbl.add_row(str(i), pwd or "[dim](empty)[/dim]",
                    f"[red]{bar}[/red] {cnt}")

    return Panel(tbl, title="[bold]🔑 Top Passwords[/bold]",
                 border_style="red", box=box.ROUNDED)

def make_top_usernames() -> Panel:
    tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold yellow",
                expand=True)
    tbl.add_column("#", style="dim", width=4)
    tbl.add_column("Username", style="yellow")
    tbl.add_column("Hits", justify="right", style="bold white")

    top = sorted(state.usernames.items(), key=lambda x: x[1], reverse=True)[:10]
    for i, (user, cnt) in enumerate(top, 1):
        tbl.add_row(str(i), user or "[dim](empty)[/dim]", str(cnt))

    return Panel(tbl, title="[bold]👤 Top Usernames[/bold]",
                 border_style="yellow", box=box.ROUNDED)

def make_top_ips() -> Panel:
    tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold bright_blue",
                expand=True)
    tbl.add_column("#", style="dim", width=4)
    tbl.add_column("Source IP", style="bright_blue")
    tbl.add_column("Hits", justify="right", style="bold white")

    top = sorted(state.src_ips.items(), key=lambda x: x[1], reverse=True)[:10]
    for i, (ip, cnt) in enumerate(top, 1):
        tbl.add_row(str(i), ip, str(cnt))

    return Panel(tbl, title="[bold]🌐 Top Attacker IPs[/bold]",
                 border_style="bright_blue", box=box.ROUNDED)

def make_port_hits() -> Panel:
    tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold green",
                expand=True)
    tbl.add_column("Port", style="green", width=6)
    tbl.add_column("Service", style="dim")
    tbl.add_column("Hits", justify="right")
    tbl.add_column("", style="green")          # bar

    top = sorted(state.port_hits.items(), key=lambda x: x[1], reverse=True)[:8]
    total_hits = sum(state.port_hits.values()) or 1
    for port, cnt in top:
        svc  = PORT_NAMES.get(port, "?")
        pct  = cnt / total_hits
        bar  = "█" * int(pct * 24)
        tbl.add_row(str(port), svc, str(cnt), bar)

    return Panel(tbl, title="[bold]🔌 Port Activity[/bold]",
                 border_style="green", box=box.ROUNDED)

def make_recent_events() -> Panel:
    tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold white",
                expand=True, show_edge=False)
    tbl.add_column("Time",    style="dim",          width=10)
    tbl.add_column("Src IP",  style="bright_blue",  width=17)
    tbl.add_column("Port",    style="green",         width=8)
    tbl.add_column("Event",   style="white",         width=20)
    tbl.add_column("Creds",   style="white")

    for ev in list(state.recent_events):
        tbl.add_row(ev["time"], ev["src"], ev["port"], ev["event"], ev["cred"])

    return Panel(tbl, title="[bold]📡 Recent Events (live)[/bold]",
                 border_style="white", box=box.ROUNDED)

def make_event_types() -> Panel:
    tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold magenta",
                expand=True)
    tbl.add_column("Event Type", style="magenta")
    tbl.add_column("Count", justify="right", style="bold white")

    sorted_types = sorted(
        [(LOGTYPE_NAMES.get(lt, f"type-{lt}"), cnt)
         for lt, cnt in state.logtype_counts.items()],
        key=lambda x: x[1], reverse=True
    )
    for name, cnt in sorted_types[:8]:
        tbl.add_row(name, str(cnt))

    return Panel(tbl, title="[bold]📋 Event Types[/bold]",
                 border_style="magenta", box=box.ROUNDED)

# ── Layout builder ─────────────────────────────────────────────────────────────
def build_layout():
    layout = Layout()

    layout.split_column(
        Layout(name="header",  size=5),
        Layout(name="row1",    size=14),
        Layout(name="row2",    size=14),
        Layout(name="recent",  minimum_size=10),
    )

    layout["row1"].split_row(
        Layout(name="stats",     ratio=1),
        Layout(name="ports",     ratio=2),
        Layout(name="evtypes",   ratio=2),
    )

    layout["row2"].split_row(
        Layout(name="passwords", ratio=3),
        Layout(name="usernames", ratio=3),
        Layout(name="ips",       ratio=3),
    )

    return layout

# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    console = Console()

    if not os.path.exists(LOG_FILE):
        console.print(f"[red]Log file not found:[/red] {LOG_FILE}")
        console.print("Usage: python3 canary_watch.py /path/to/opencanary.log")
        sys.exit(1)

    console.print(f"[yellow]Watching[/yellow] [bold]{LOG_FILE}[/bold] ...")
    time.sleep(0.5)

    layout = build_layout()

    with Live(layout, console=console, refresh_per_second=REFRESH_HZ,
              screen=True):
        while True:
            tail_file()

            layout["header"].update(make_header())
            layout["stats"].update(make_stats())
            layout["ports"].update(make_port_hits())
            layout["evtypes"].update(make_event_types())
            layout["passwords"].update(make_top_passwords())
            layout["usernames"].update(make_top_usernames())
            layout["ips"].update(make_top_ips())
            layout["recent"].update(make_recent_events())

            time.sleep(1 / REFRESH_HZ)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        Console().print("\n[yellow]Stopped.[/yellow]")
