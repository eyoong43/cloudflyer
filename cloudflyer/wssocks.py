import asyncio
import shlex
from shutil import which
import subprocess
from pathlib import Path
import time
import platform
from typing import Optional


class WSSocks:
    def __init__(self):
        self.system = platform.system()
        self.process: Optional[subprocess.Popen] = None
    
    @property
    def executable_path(self) -> Path:
        """Get path to the executable"""
        exe_name = "wssocks.exe" if self.system == "Windows" else "wssocks"
        if Path(exe_name).exists():
            return Path(exe_name)
        exe_path = which(exe_name)
        if exe_path:
            return Path(exe_path)
        else:
            return None

    def execute(self, *args) -> subprocess.Popen:
        """Execute wssocks with given arguments and return Popen object"""
        if not self.executable_path:
            raise RuntimeError(f'{self.executable_path} not found in current dir')
        return subprocess.Popen([str(self.executable_path), *args])

    def start(self, token: str, url: str, port: int, threads: int = 1) -> Optional[str]:
        """Start wssocks connector

        Args:
            token: Authentication token
            port: Local port to listen on

        Returns:
            Error message if failed, None if successful
        """
        if self.process and self.process.poll() is None:
            raise RuntimeError("WSSocks is already running")

        args = ["client", "-t", token, "-u", url, "-T", str(threads), "-p", str(port), "-dd"]

        self.process = self.execute(*args)

        time.sleep(3)

        if self.process.poll() is not None:
            return False
        return True

    def stop(self) -> None:
        """Stop wssocks server if running"""
        if self.process:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
            self.process = None
