"""Cancellable external recovery workers with process and output limits."""
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import time

from .carve import checkpoint
from .models import EraseProofError
from .runtime import system_environment


def usage(root):
    total = files = 0
    for folder, directories, names in os.walk(root):
        if any((Path(folder)/name).is_symlink() for name in directories):
            raise EraseProofError("Recovery worker created an unexpected directory symlink.")
        for name in names:
            path = Path(folder)/name
            try:
                info = path.lstat()
            except FileNotFoundError:
                # PhotoRec renames/removes provisional outputs while running.
                # The final inventory is repeated after the whole process group
                # stops; a transient disappearance is not an accounting error.
                continue
            if not stat.S_ISREG(info.st_mode):
                raise EraseProofError("Recovery worker created an unexpected symlink or special file.")
            total += info.st_size
            files += 1
    return total, files


def stop(process):
    # The leader can exit before its children. Clean the owned group even when
    # poll() already reports a completed leader, then reap our direct child.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        process.wait(timeout=3)
        return
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        pass
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=3)


def run(command, root, name, timeout, cancel=None, fd=None, output_limit=8*1024**3, *, bundled=False, per_file_limit=256*1024**2):
    if not 0 < per_file_limit <= 16*1024**3 or not 0 < output_limit <= 16*1024**3:
        raise EraseProofError('Invalid external recovery output limits.')
    limiter = shutil.which("prlimit")
    if not limiter:
        return {"status": "limits-unavailable", "returncode": None, "duration_seconds": 0}
    started = time.monotonic()
    prefix = [limiter, "--as=2147483648", "--cpu="+str(timeout+10), "--fsize="+str(per_file_limit), "--core=0", "--"]
    stdout, stderr = root/(name+".stdout.log"), root/(name+".stderr.log")
    if bundled and getattr(sys, "frozen", False):
        # Apply bundled dependencies to the helper only. prlimit and other
        # system executables keep the clean system library environment.
        command = ["/usr/bin/env", "LD_LIBRARY_PATH="+sys._MEIPASS, *command]
    with stdout.open("xb") as out, stderr.open("xb") as err:
        process = subprocess.Popen(prefix+list(map(str, command)), cwd=root, stdin=subprocess.DEVNULL,
                                   stdout=out, stderr=err, start_new_session=True,
                                   pass_fds=() if fd is None else (fd,),
                                   env={**system_environment(), "TERM": "dumb"})
        status = "completed"
        try:
            next_check = 0
            while process.poll() is None:
                checkpoint(cancel)
                elapsed = time.monotonic()-started
                if elapsed >= timeout:
                    status = "timeout"
                    break
                if elapsed >= next_check:
                    total, files = usage(root)
                    if total > output_limit or files > 10_000:
                        status = "output-limit"
                        break
                    next_check = elapsed+.5
                time.sleep(.05)
        finally:
            stop(process)
    total, files = usage(root)
    if total > output_limit or files > 10_000:
        status = "output-limit"
    if status == "completed" and process.returncode:
        status = "failed"
    return {"status": status, "returncode": process.returncode,
            "duration_seconds": time.monotonic()-started,
            "stdout_log": str(stdout), "stderr_log": str(stderr),
            "limits": {"address_space_bytes": 2147483648, "per_file_bytes": per_file_limit,
                       "output_bytes": output_limit, "output_files": 10_000, "wall_seconds": timeout}}
