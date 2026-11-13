import argparse
import contextlib
import fcntl
import json
import os
import plistlib
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from datetime import datetime
from pathlib import Path

from engine import prepare_engine
from firmware import BUILD
from prepare import prepare, report, verify_profile

RUNTIME = Path(__file__).resolve().parent
RESOURCES = RUNTIME.parent
SUPPORT = Path.home() / "Library/Application Support/NonUI"
DEFAULT_UTM = Path("/Applications/UTM.app")


def read_json(path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def write_json(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


@contextlib.contextmanager
def locked(directory):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (directory / "lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError("NonUI is already importing or running.") from error
        yield


def send_stop(state):
    with (Path(state["ipc"]) / "control.jsonl").open("ab", buffering=0) as control:
        control.write(b'{"type":"shutdown"}\n')


def stop(directory):
    state_file = directory / "session.json"
    state = read_json(state_file)
    if not state.get("ipc"):
        report("Stopped")
        return
    if state.get("state") != "stopped":
        try:
            send_stop(state)
        except FileNotFoundError:
            if read_json(state_file).get("state") != "stopped":
                raise
        deadline = time.monotonic() + 20
        while read_json(state_file).get("state") != "stopped":
            if time.monotonic() >= deadline:
                raise TimeoutError("NonUI did not stop within 20 seconds.")
            time.sleep(0.1)
    report("Stopped")


def reset(directory):
    state = read_json(directory / "session.json") if directory.exists() else {}
    if state.get("ipc") and state.get("state") != "stopped":
        stop(directory)
    deadline = time.monotonic() + 5
    while True:
        try:
            with locked(directory):
                for name in (
                    BUILD,
                    "Runs",
                    "Frameworks",
                    "session.json",
                    "import.log",
                    "launch.log",
                ):
                    path = directory / name
                    if path.is_symlink() or path.is_file():
                        path.unlink()
                    elif path.is_dir():
                        shutil.rmtree(path)
            break
        except ValueError as error:
            if "already importing" not in str(error) or time.monotonic() >= deadline:
                raise
            time.sleep(0.1)
    report("Removed")


def terminate_group(process):
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()


def launch(directory, profile, engine, seconds, window):
    run = directory / "Runs" / datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    run.mkdir(parents=True, mode=0o700)
    state_file = directory / "session.json"
    guest = viewer = None
    stopping = False

    def request_stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, request_stop)
    with tempfile.TemporaryDirectory(prefix="nonui-", dir="/tmp") as temporary:
        ipc = Path(temporary)
        (ipc / "control.jsonl").touch()
        state = {"state": "booting", "ipc": str(ipc), "run": str(run)}
        write_json(state_file, state)
        try:
            report(f"Boot log {run / 'boot.log'}")
            gate = subprocess.run(
                [str(RESOURCES / "host-ready"), str(directory)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            (run / "host-ready.log").write_text(gate.stdout)
            report(gate.stdout.rstrip())
            if gate.returncode or not gate.stdout.startswith("READY "):
                return gate.returncode or 1
            if stopping:
                return 0

            with (run / "boot.log").open("wb") as log:
                guest = subprocess.Popen(
                    [
                        sys.executable,
                        "-sEBu",
                        str(RUNTIME / "guest.py"),
                        str(profile),
                        str(run),
                        str(ipc),
                        str(RESOURCES / "runner"),
                        str(engine),
                        str(ipc),
                        str(seconds),
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
                deadline = time.monotonic() + seconds + 20
                while guest.poll() is None:
                    if (
                        stopping
                        or time.monotonic() >= deadline
                        or (viewer and viewer.poll() is not None)
                    ):
                        send_stop(state)
                        try:
                            guest.wait(timeout=7)
                        except subprocess.TimeoutExpired:
                            terminate_group(guest)
                        break
                    if state["state"] == "booting":
                        status = read_json(ipc / "live-status.json")
                        if (
                            status.get("state") == "running"
                            and (ipc / "frames.sock").exists()
                        ):
                            if window:
                                viewer = subprocess.Popen(
                                    [
                                        str(
                                            RESOURCES.parent
                                            / "Helpers/NonUI Display.app/Contents/MacOS/NonUIDisplay"
                                        ),
                                        str(ipc / "frames.sock"),
                                        str(ipc / "control.jsonl"),
                                    ],
                                    stdout=log,
                                    stderr=subprocess.STDOUT,
                                )
                            state["state"] = "running"
                            write_json(state_file, state)
                            report("SwitchBoard")
                    time.sleep(0.1)
            result = read_json(run / "result.json")
            if result.get("error"):
                report(result["error"])
            elif (
                state["state"] == "booting"
                and not result.get("live_display_closed_by_user")
                and not stopping
            ):
                report("The guest stopped before SwitchBoard appeared.")
                return guest.returncode or 1
            return 1 if result.get("error") else guest.returncode or 0
        finally:
            if guest is not None:
                terminate_group(guest)
            if viewer is not None and viewer.poll() is None:
                viewer.terminate()
                try:
                    viewer.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    viewer.kill()
                    viewer.wait()
            stats = read_json(ipc / "viewer-stats.json")
            if stats:
                write_json(run / "viewer-stats.json", stats)
            write_json(state_file, {"state": "stopped", "run": str(run)})


def main():
    parser = argparse.ArgumentParser(prog="nonui")
    parser.add_argument("--data-dir", type=Path, default=SUPPORT)
    commands = parser.add_subparsers(dest="command", required=True)
    importer = commands.add_parser("import")
    importer.add_argument("--experimental", action="store_true")
    importer.add_argument("files", type=Path, nargs="+")
    boot = commands.add_parser("boot")
    boot.add_argument("--utm", type=Path, default=DEFAULT_UTM)
    boot.add_argument(
        "--seconds", type=int, choices=range(120, 881), metavar="120-880", default=880
    )
    boot.add_argument("--no-window", action="store_true")
    commands.add_parser("stop")
    commands.add_parser("reset")
    commands.add_parser("status")
    arguments = parser.parse_args()
    directory = arguments.data_dir.expanduser().resolve()
    profile = directory / BUILD

    if arguments.command == "status":
        print(
            json.dumps(
                read_json(directory / "session.json") or {"state": "stopped"}, indent=2
            )
        )
    elif arguments.command == "stop":
        stop(directory)
    elif arguments.command == "reset":
        reset(directory)
    else:
        with locked(directory):
            if arguments.command == "import":
                if profile.exists():
                    verify_profile(profile)
                    report(f"{BUILD} is already imported.")
                else:
                    prepare(
                        profile,
                        [path.resolve() for path in arguments.files],
                        RESOURCES / "RootBuilder",
                        experimental=arguments.experimental,
                    )
            else:
                if not profile.is_dir():
                    raise ValueError(f"Import {BUILD} before booting.")
                verify_profile(profile)
                engine = prepare_engine(
                    arguments.utm.expanduser().resolve(), directory / "Frameworks"
                )
                return launch(
                    directory,
                    profile,
                    engine,
                    arguments.seconds,
                    not arguments.no_window,
                )
    return 0


if __name__ == "__main__":
    os.umask(0o077)
    try:
        sys.exit(main())
    except (
        OSError,
        ValueError,
        subprocess.CalledProcessError,
        KeyError,
        plistlib.InvalidFileException,
        tarfile.TarError,
        zipfile.BadZipFile,
        TimeoutError,
    ) as error:
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            print(
                error.stderr.decode(errors="replace").strip(),
                file=sys.stderr,
                flush=True,
            )
        else:
            print(str(error), file=sys.stderr, flush=True)
        sys.exit(1)
