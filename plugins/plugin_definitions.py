from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class PluginArgument:
    key: str
    label: str
    arg_type: str = "text"  # text | int | bool | file | offset
    required: bool = False
    default: Any = ""
    help_text: str = ""


@dataclass(slots=True)
class PluginDefinition:
    name: str
    category: str
    description: str
    vol2_name: str | None = None
    vol3_name: str | None = None
    supports_vol2: bool = True
    supports_vol3: bool = True
    args: list[PluginArgument] = field(default_factory=list)


PLUGIN_CATEGORIES = [
    "Process Analysis",
    "Network Analysis",
    "Registry Analysis",
    "File System Artifacts",
    "Malware Detection",
    "Kernel Analysis",
    "Credential Extraction",
    "Timeline / Forensic Correlation",
]

CATEGORY_DESCRIPTIONS = {
    "Process Analysis": "Enumerates running and hidden processes, command lines, modules, and process relationships.",
    "Network Analysis": "Recovers socket activity, scan artifacts, and protocol-level indicators of communication.",
    "Registry Analysis": "Extracts registry hives, keys, and values to identify persistence and configuration changes.",
    "File System Artifacts": "Locates files, MFT structures, and cached artifacts relevant to user and malware activity.",
    "Malware Detection": "Detects injected code, suspicious memory regions, and YARA-based indicators.",
    "Kernel Analysis": "Inspects kernel objects, drivers, SSDT/IDT hooks, callbacks, and low-level tampering.",
    "Credential Extraction": "Analyzes authentication material and secret stores for account compromise evidence.",
    "Timeline / Forensic Correlation": "Builds chronological event traces for cross-artifact investigation and reporting.",
}


def _p(
    name: str,
    category: str,
    description: str,
    vol2_name: str | None,
    vol3_name: str | None,
    supports_vol2: bool = True,
    supports_vol3: bool = True,
    args: list[PluginArgument] | None = None,
) -> PluginDefinition:
    return PluginDefinition(
        name=name,
        category=category,
        description=description,
        vol2_name=vol2_name,
        vol3_name=vol3_name,
        supports_vol2=supports_vol2,
        supports_vol3=supports_vol3,
        args=args or [],
    )


PLUGINS: list[PluginDefinition] = [
    _p("pslist", "Process Analysis", "Lists active processes.", "pslist", "windows.pslist"),
    _p("pstree", "Process Analysis", "Displays process parent-child hierarchy.", "pstree", "windows.pstree"),
    _p("psxview", "Process Analysis", "Cross-view process checks for hidden execution.", "psxview", "windows.psxview"),
    _p("cmdline", "Process Analysis", "Shows process command lines.", "cmdline", "windows.cmdline", args=[PluginArgument("pid", "PID", "int", False, "", "Filter by Process ID")]),
    _p("dlllist", "Process Analysis", "Lists process-loaded DLLs.", "dlllist", "windows.dlllist", args=[PluginArgument("pid", "PID", "int", False, "", "Filter by Process ID")]),
    _p("handles", "Process Analysis", "Enumerates open handles.", "handles", "windows.handles", args=[PluginArgument("pid", "PID", "int", False, "", "Filter by Process ID")]),
    _p("threads", "Process Analysis", "Lists process threads.", "threads", "windows.threads"),
    _p("envars", "Process Analysis", "Prints process environment variables.", "envars", "windows.envars"),
    _p("getsids", "Process Analysis", "Lists process security identifiers.", "getsids", "windows.getsids"),
    _p("privs", "Process Analysis", "Inspects process token privileges.", "privs", "windows.privileges"),
    _p("sessions", "Process Analysis", "Displays interactive sessions.", "sessions", "windows.sessions"),
    _p("joblinks", "Process Analysis", "Analyzes process job objects.", "joblinks", "windows.joblinks"),

    _p("netscan", "Network Analysis", "Enumerates network endpoints and sockets.", "netscan", "windows.netscan"),
    _p("connscan", "Network Analysis", "Scans memory for network connections.", "connscan", None, supports_vol3=False),
    _p("sockscan", "Network Analysis", "Scans memory for socket objects.", "sockscan", None, supports_vol3=False),
    _p("connections", "Network Analysis", "Lists active network connections (legacy).", "connections", None, supports_vol3=False),
    _p("sockets", "Network Analysis", "Lists socket objects (legacy).", "sockets", None, supports_vol3=False),
    _p("netstat", "Network Analysis", "Summarizes network communication artifacts.", "connscan", "windows.netstat", supports_vol2=True),

    _p("hivelist", "Registry Analysis", "Lists loaded registry hives.", "hivelist", "windows.registry.hivelist"),
    _p("printkey", "Registry Analysis", "Prints key/value data for a registry path.", "printkey", "windows.registry.printkey", args=[PluginArgument("key", "Registry Key", "text", True, "", "Registry key path")]),
    _p("hivescan", "Registry Analysis", "Scans for registry hive signatures.", "hivescan", "windows.registry.hivescan"),
    _p("dumpregistry", "Registry Analysis", "Extracts registry hive data to disk.", "dumpregistry", None, supports_vol3=False),
    _p("userassist", "Registry Analysis", "Parses UserAssist execution artifacts.", "userassist", "windows.registry.userassist"),
    _p("shimcache", "Registry Analysis", "Extracts application compatibility cache.", "shimcache", "windows.registry.shimcache"),
    _p("amcache", "Registry Analysis", "Parses Amcache execution history.", None, "windows.amcache", supports_vol2=False),

    _p("filescan", "File System Artifacts", "Scans for file objects in memory.", "filescan", "windows.filescan"),
    _p("dumpfiles", "File System Artifacts", "Dumps cached file objects.", "dumpfiles", "windows.dumpfiles", args=[PluginArgument("virtaddr", "Virtual Address", "offset", False, "", "File object address")]),
    _p("mftparser", "File System Artifacts", "Parses NTFS MFT structures.", "mftparser", "windows.mftscan"),
    _p("yarascan-files", "File System Artifacts", "YARA scans backed file regions.", "yarascan", "yarascan.YaraScan", args=[PluginArgument("yara_file", "YARA Rule File", "file", False, "", "Path to YARA rules")]),
    _p("shellbags", "File System Artifacts", "Parses Shellbag navigation artifacts.", "shellbags", "windows.registry.shellbags"),
    _p("clipboard", "File System Artifacts", "Recovers clipboard artifacts.", "clipboard", "windows.clipboard"),

    _p("malfind", "Malware Detection", "Detects injected code regions.", "malfind", "windows.malfind", args=[PluginArgument("pid", "PID", "int", False, "", "Filter by Process ID")]),
    _p("yarascan", "Malware Detection", "Scans memory using YARA signatures.", "yarascan", "yarascan.YaraScan", args=[PluginArgument("yara_file", "YARA Rule File", "file", False, "", "Path to YARA rules"), PluginArgument("pid", "PID", "int", False, "", "Optional process ID")]),
    _p("apihooks", "Malware Detection", "Identifies API hooking patterns.", "apihooks", "windows.apihooks"),
    _p("callbacks", "Malware Detection", "Lists kernel callback routines.", "callbacks", "windows.callbacks"),
    _p("ldrmodules", "Malware Detection", "Detects unlinked or hidden modules.", "ldrmodules", "windows.ldrmodules"),
    _p("driverirp", "Malware Detection", "Checks driver IRP handlers.", "driverirp", "windows.driverirp"),
    _p("modscan", "Malware Detection", "Scans for loaded modules.", "modscan", "windows.modscan"),
    _p("mutantscan", "Malware Detection", "Finds mutex objects used by malware.", "mutantscan", "windows.mutantscan"),

    _p("modules", "Kernel Analysis", "Lists kernel modules.", "modules", "windows.modules"),
    _p("driverscan", "Kernel Analysis", "Scans memory for driver objects.", "driverscan", "windows.driverscan"),
    _p("ssdt", "Kernel Analysis", "Inspects SSDT entries.", "ssdt", "windows.ssdt"),
    _p("idt", "Kernel Analysis", "Inspects IDT entries.", "idt", "windows.idt"),
    _p("gdt", "Kernel Analysis", "Inspects GDT entries.", "gdt", "windows.gdt"),
    _p("kpcrscan", "Kernel Analysis", "Scans for KPCR structures.", "kpcrscan", "windows.kpcrs"),
    _p("poolscanner", "Kernel Analysis", "Scans memory pools for forensic objects.", "poolscanner", "windows.poolscanner"),
    _p("objtypescan", "Kernel Analysis", "Enumerates kernel object types.", "objtypescan", "windows.objtypescan"),
    _p("devicetree", "Kernel Analysis", "Builds kernel device tree view.", "devicetree", "windows.devicetree"),

    _p("hashdump", "Credential Extraction", "Extracts local account password hashes.", "hashdump", None, supports_vol3=False),
    _p("lsadump", "Credential Extraction", "Extracts LSA secrets.", "lsadump", None, supports_vol3=False),
    _p("cachedump", "Credential Extraction", "Extracts cached domain credential hashes.", "cachedump", None, supports_vol3=False),
    _p("secretsdump", "Credential Extraction", "Pulls stored secret material from memory artifacts.", None, "windows.lsadump", supports_vol2=False),
    _p("mimikatz", "Credential Extraction", "Parses in-memory credential traces.", "mimikatz", None, supports_vol3=False),

    _p("timeliner", "Timeline / Forensic Correlation", "Generates unified forensic timeline entries.", "timeliner", "timeliner.Timeliner"),
    _p("psscan", "Timeline / Forensic Correlation", "Scans for EPROCESS structures, including exited tasks.", "psscan", "windows.psscan"),
    _p("shimcachemem", "Timeline / Forensic Correlation", "Builds execution timeline from ShimCache data.", "shimcache", "windows.registry.shimcache"),
    _p("consoles", "Timeline / Forensic Correlation", "Extracts console history and commands.", "consoles", "windows.consoles"),
    _p("cmdscan", "Timeline / Forensic Correlation", "Recovers command history buffers.", "cmdscan", "windows.cmdscan"),
]


def get_plugins_for_version(version: str) -> list[PluginDefinition]:
    if version == "2":
        return [p for p in PLUGINS if p.supports_vol2]
    return [p for p in PLUGINS if p.supports_vol3]


def find_plugin(name: str) -> PluginDefinition | None:
    return next((p for p in PLUGINS if p.name == name), None)


def category_plugin_counts(version: str) -> dict[str, int]:
    plugins = get_plugins_for_version(version)
    counts = {cat: 0 for cat in PLUGIN_CATEGORIES}
    for plugin in plugins:
        counts[plugin.category] = counts.get(plugin.category, 0) + 1
    return counts
