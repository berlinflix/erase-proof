"""Boot the ISO in a disposable QEMU VM with no hard disks attached.

Use --kernel/--initrd to request the generated-image engine self-test. Omit
them to test the ISO's real GRUB BIOS/UEFI route and capture it for visual QA.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser()
parser.add_argument("iso", type=Path)
parser.add_argument("--output", required=True, type=Path)
parser.add_argument("--kernel", type=Path)
parser.add_argument("--initrd", type=Path)
parser.add_argument("--uefi", action="store_true")
parser.add_argument("--timeout", type=int, default=240)
args = parser.parse_args()
if args.iso.suffix != ".iso" or not args.iso.is_file() or bool(args.kernel) != bool(args.initrd):
    parser.error("Provide an existing ISO and either both kernel/initrd paths or neither.")
args.output.mkdir(parents=True, exist_ok=False)
out = args.output.resolve()
serial = out/"serial.log"
try:
    with open("/dev/kvm", "rb", buffering=0) as device:
        acceleration = "kvm" if fcntl.ioctl(device, 0xAE00) == 12 else "tcg"
except OSError:
    acceleration = "tcg"

with tempfile.TemporaryDirectory(prefix="ep-qemu-") as control, (out/"qemu.log").open("wb") as errors:
    monitor = Path(control)/"qmp.sock"
    command = ["qemu-system-x86_64", "-name", "EraseProof-build-check", "-accel", acceleration,
               "-cpu", "host" if acceleration == "kvm" else "max", "-m", "4096", "-smp", "2",
               "-cdrom", str(args.iso.resolve()), "-boot", "d", "-display", "none", "-vga", "std",
               "-nic", "none", "-no-reboot", "-serial", "file:"+str(serial),
               "-qmp", f"unix:{monitor},server=on,wait=off"]
    if args.uefi:
        firmware = Path("/usr/share/OVMF")
        variables = Path(control)/"VARS.fd"
        shutil.copyfile(firmware/"OVMF_VARS_4M.fd", variables)
        command.extend(["-drive", f"if=pflash,format=raw,readonly=on,file={firmware/'OVMF_CODE_4M.fd'}",
                        "-drive", f"if=pflash,format=raw,file={variables}"])
    if args.kernel:
        command.extend(["-kernel", str(args.kernel.resolve()), "-initrd", str(args.initrd.resolve()),
                        "-append", "boot=casper quiet username=eraseproof hostname=eraseproof noprompt noeject eraseproof.selftest=1 systemd.mask=serial-getty@ttyS0.service console=tty0 console=ttyS0,115200n8"])
    vm = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=errors)
    started, passed = time.monotonic(), False
    try:
        while time.monotonic()-started < args.timeout:
            if vm.poll() is not None:
                raise RuntimeError("QEMU exited; inspect "+str(out/"qemu.log"))
            text = serial.read_text(errors="replace") if serial.exists() else ""
            if args.kernel and "ERASEPROOF_BOOT_CHECK_PASS" in text:
                passed = True
                break
            if not args.kernel and "login:" in text:
                passed = True
                break
            time.sleep(1)
        if not passed:
            raise RuntimeError("Live boot check timed out; inspect "+str(serial))
        # Allow the independent tty1 graphical session to settle.
        time.sleep(15)
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(15)
            connection.connect(str(monitor))
            stream = connection.makefile("rwb")
            json.loads(stream.readline())
            def execute(name, arguments=None):
                stream.write((json.dumps({"execute": name, "arguments": arguments or {}})+"\n").encode())
                stream.flush()
                while True:
                    result = json.loads(stream.readline())
                    if "error" in result:
                        raise RuntimeError(str(result["error"]))
                    if "return" in result:
                        return result["return"]
            execute("qmp_capabilities")
            execute("screendump", {"filename": str(out/"screen.ppm")})
        from PIL import Image
        with Image.open(out/"screen.ppm") as screen:
            screen.save(out/"screen.png")
        report = {"iso": str(args.iso.resolve()), "acceleration": acceleration, "hard_disks_attached": 0,
                  "mode": "generated-image-engine-selftest" if args.kernel else ("UEFI-GRUB" if args.uefi else "BIOS-GRUB"),
                  "serial_boot_condition": "passed", "duration_seconds": time.monotonic()-started,
                  "screenshot": str(out/"screen.png"), "visual_gui_review": "required", "virtualbox_tested": False}
        (out/"boot-result.json").write_text(json.dumps(report, indent=2)+"\n")
        print(json.dumps(report, indent=2))
    finally:
        vm.terminate()
        try:
            vm.wait(timeout=15)
        except subprocess.TimeoutExpired:
            vm.kill()
            vm.wait()
