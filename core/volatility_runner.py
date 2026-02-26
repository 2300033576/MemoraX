from __future__ import annotations

import importlib.util
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from plugins.plugin_definitions import PluginDefinition


@dataclass(slots=True)
class VolatilityEnvironment:
    vol2_cmd: list[str] | None
    vol3_cmd: list[str] | None


def _module_has_main(module_name: str) -> bool:
    try:
        return importlib.util.find_spec(f"{module_name}.__main__") is not None
    except ModuleNotFoundError:
        return False


def _detect_cmd(candidates: list[str]) -> str | None:
    for cmd in candidates:
        if shutil.which(cmd):
            return cmd
    return None


def detect_volatility() -> VolatilityEnvironment:
    vol2 = _detect_cmd(["volatility", "vol.py"])
    vol3 = _detect_cmd(["vol", "volatility3", "volatility3.py", "vol.py"])

    vol2_cmd = [vol2] if vol2 else None
    vol3_cmd = [vol3] if vol3 else None

    if not vol3_cmd and importlib.util.find_spec("volatility3"):
        if _module_has_main("volatility3"):
            vol3_cmd = [sys.executable, "-m", "volatility3"]
        elif importlib.util.find_spec("volatility3.cli"):
            vol3_cmd = [
                sys.executable,
                "-c",
                "import sys; from volatility3.cli import main; sys.argv=['vol'] + sys.argv[1:]; main()",
            ]

    if not vol2_cmd and importlib.util.find_spec("volatility") and _module_has_main("volatility"):
        vol2_cmd = [sys.executable, "-m", "volatility"]

    return VolatilityEnvironment(vol2_cmd=vol2_cmd, vol3_cmd=vol3_cmd)


def _install_with_pip(package_name: str) -> tuple[bool, str]:
    cmd = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        package_name,
    ]
    completed = subprocess.run(cmd, capture_output=True, text=True)
    output = (completed.stdout or "") + ("\n" + completed.stderr if completed.stderr else "")
    return completed.returncode == 0, output.strip()


def ensure_volatility_installed() -> tuple[VolatilityEnvironment, list[str]]:
    messages: list[str] = []
    env = detect_volatility()

    if not env.vol3_cmd:
        ok, output = _install_with_pip("volatility3")
        if ok:
            messages.append("Volatility 3 was not found and has been installed automatically.")
        else:
            messages.append("Automatic installation of Volatility 3 failed.")
            if output:
                messages.append(output[:900])
        env = detect_volatility()

    if not env.vol2_cmd:
        ok, output = _install_with_pip("volatility")
        if ok:
            messages.append("Volatility 2 package was installed automatically.")
        else:
            messages.append(
                "Volatility 2 could not be installed automatically (often incompatible with modern Python)."
            )
            if output:
                messages.append(output[:900])
        env = detect_volatility()

    if env.vol2_cmd or env.vol3_cmd:
        messages.append("Volatility environment check complete.")

    return env, messages


class VolatilityCommandBuilder:
    def __init__(self, env: VolatilityEnvironment) -> None:
        self.env = env

    def available_versions(self) -> list[str]:
        versions: list[str] = []
        if self.env.vol2_cmd:
            versions.append("2")
        if self.env.vol3_cmd:
            versions.append("3")
        return versions

    def validate(self, version: str) -> tuple[bool, str]:
        if version == "2" and not self.env.vol2_cmd:
            return False, "Volatility 2 executable not detected in PATH"
        if version == "3" and not self.env.vol3_cmd:
            return False, "Volatility 3 executable not detected in PATH"
        return True, "OK"

    def build_command(
        self,
        version: str,
        plugin: PluginDefinition,
        image_path: str,
        plugin_params: dict[str, str | bool | int],
        profile: str = "",
    ) -> list[str]:
        path = str(Path(image_path))
        dump_output_dir = Path("reports") / "dumps"

        if version == "2":
            if not self.env.vol2_cmd:
                raise RuntimeError("Volatility 2 not detected")
            if not plugin.vol2_name:
                raise ValueError(f"Plugin {plugin.name} unsupported on Volatility 2")
            cmd = [*self.env.vol2_cmd, "-f", path]
            if profile:
                cmd.append(f"--profile={profile}")
            cmd.append(plugin.vol2_name)
            if plugin.name == "dumpfiles":
                dump_output_dir.mkdir(parents=True, exist_ok=True)
                cmd.extend(["--dump-dir", str(dump_output_dir)])
        else:
            if not self.env.vol3_cmd:
                raise RuntimeError("Volatility 3 not detected")
            if not plugin.vol3_name:
                raise ValueError(f"Plugin {plugin.name} unsupported on Volatility 3")
            cmd = [*self.env.vol3_cmd, "-f", path]
            if plugin.name == "dumpfiles":
                dump_output_dir.mkdir(parents=True, exist_ok=True)
                cmd.extend(["-o", str(dump_output_dir)])
            cmd.append(plugin.vol3_name)

        for key, value in plugin_params.items():
            if value in ("", None, False):
                continue
            normalized = key.replace("_", "-")
            if isinstance(value, bool):
                cmd.append(f"--{normalized}")
            else:
                cmd.extend([f"--{normalized}", str(value)])

        return cmd


def command_to_str(command: list[str]) -> str:
    return " ".join(shlex.quote(item) for item in command)
