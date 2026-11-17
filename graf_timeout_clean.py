#!/usr/bin/env python3
"""Time-limit a multiprocessing GRAF command without broadcasting SIGINT to workers.

Linux/POSIX only. Starts the workload in an isolated process group, sends SIGINT
only to its main PID on expiry, waits for cooperative cleanup, then removes any
remaining children. Returns 124 for a reached deadline, otherwise child status.
"""
import argparse
import os
import signal
import subprocess
import sys
import time


def duration(text):
    t = str(text).strip().lower()
    suffix = {"s": 1, "m": 60, "h": 3600}
    try:
        secs = float(t[:-1]) * suffix[t[-1]] if t[-1:] in suffix else float(t)
        if not (0 < secs < float("inf")):
            raise ValueError
        return secs
    except (ValueError, IndexError) as exc:
        raise argparse.ArgumentTypeError("duration must be positive, e.g. 5m or 1h") from exc


def run():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--duration", type=duration, required=True)
    ap.add_argument("--grace", type=duration, default=180, help="seconds to wait for main process after SIGINT (default 180)")
    ap.add_argument("--term-grace", type=duration, default=10)
    ap.add_argument("command", nargs=argparse.REMAINDER)
    args = ap.parse_args()
    cmd = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not cmd:
        ap.error("a command is required after --")
    if os.name != "posix":
        ap.error("Linux/POSIX only")

    print(f"[deadline] starting command, duration={args.duration:g}s, grace={args.grace:g}s", flush=True)
    p = subprocess.Popen(cmd, start_new_session=True)
    timed_out = False
    interrupted = False

    def send_group(sig):
        try:
            os.killpg(p.pid, sig)
        except ProcessLookupError:
            pass

    def group_alive():
        try:
            os.killpg(p.pid, 0)
            return True
        except ProcessLookupError:
            return False

    try:
        try:
            p.wait(timeout=args.duration)
        except subprocess.TimeoutExpired:
            timed_out = True
            print("[deadline] reached; SIGINT to GRAF main PID only", flush=True)
            if p.poll() is None:
                p.send_signal(signal.SIGINT)
            try:
                p.wait(timeout=args.grace)
            except subprocess.TimeoutExpired:
                print("[deadline] main did not exit in grace period; forcing process-group cleanup", file=sys.stderr, flush=True)
        except KeyboardInterrupt:
            interrupted = True
            print("[deadline] manual interrupt; SIGINT to main PID only", flush=True)
            if p.poll() is None:
                p.send_signal(signal.SIGINT)
            try:
                p.wait(timeout=args.grace)
            except subprocess.TimeoutExpired:
                pass
    finally:
        # GRAF may leave multiprocessing workers behind after its main process exits.
        # Do not touch the Docker Redis process: it is outside this private process group.
        if group_alive():
            print("[deadline] terminating remaining GRAF process-group members", flush=True)
            send_group(signal.SIGTERM)
            limit = time.monotonic() + args.term_grace
            while group_alive() and time.monotonic() < limit:
                time.sleep(0.2)
            if group_alive():
                print("[deadline] SIGKILL remaining process-group members", flush=True)
                send_group(signal.SIGKILL)
        if p.poll() is None:
            try:
                p.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass

    if interrupted:
        print("[deadline] interrupted by user", flush=True)
        return 130
    if timed_out:
        print("[deadline] time limit finished; returning 124", flush=True)
        return 124
    return p.returncode if p.returncode is not None else 1


if __name__ == "__main__":
    sys.exit(run())
