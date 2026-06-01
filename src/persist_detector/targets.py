from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase


SOFTWARE_BRANCHES: tuple[str, ...] = (
    "Classes",
    "Microsoft\\Active Setup\\Installed Components",
    "Microsoft\\Command Processor",
    "Microsoft\\Ctf\\LangBarAddin",
    "Microsoft\\Internet Explorer\\Extensions",
    "Microsoft\\Netsh",
    "Microsoft\\Office",
    "Microsoft\\Office test\\Special\\Perf",
    "Microsoft\\Windows CE Services\\AutoStartOnConnect\\MicrosoftActiveSync",
    "Microsoft\\Windows CE Services\\AutoStartOnDisconnect\\MicrosoftActiveSync",
    "Microsoft\\Windows NT\\CurrentVersion",
    "Microsoft\\Windows\\CurrentVersion",
    "Microsoft\\Windows\\Windows Error Reporting\\Hangs",
    "Policies\\Microsoft\\Windows\\Control Panel\\Desktop",
    "Policies\\Microsoft\\Windows\\System\\Scripts",
    "Wow6432Node\\Microsoft\\Windows\\CurrentVersion",
    "Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion",
)

SYSTEM_BRANCHES: tuple[str, ...] = (
    "ControlSet001\\Control\\BootVerificationProgram",
    "ControlSet001\\Control\\Lsa\\Notification Packages",
    "ControlSet001\\Control\\Lsa\\OSConfig\\Security Packages",
    "ControlSet001\\Control\\Lsa\\Security Packages",
    "ControlSet001\\Control\\NetworkProvider\\Order",
    "ControlSet001\\Control\\Print\\Environments",
    "ControlSet001\\Control\\Print\\Monitors",
    "ControlSet001\\Control\\SafeBoot",
    "ControlSet001\\Control\\ServiceControlManagerExtension",
    "ControlSet001\\Control\\Session Manager",
    "ControlSet001\\Control\\Terminal Server\\Wds\\rdpwd",
    "ControlSet001\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
    "ControlSet001\\Services",
    "Setup",
)

NTUSER_BRANCHES: tuple[str, ...] = (
    "Software\\Microsoft",
    "Software\\Policies\\Microsoft\\Windows\\System\\Scripts",
    "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion",
    "Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion",
    "System\\CurrentControlSet\\Control",
    "System\\CurrentControlSet\\Services",
    "System\\Setup",
    "Environment",
    "Control Panel\\Desktop",
)

USRCLASS_BRANCHES: tuple[str, ...] = ("ROOT",)

TARGET_BRANCHES: dict[str, tuple[str, ...]] = {
    "SOFTWARE": SOFTWARE_BRANCHES,
    "SYSTEM": SYSTEM_BRANCHES,
    "NTUSER": NTUSER_BRANCHES,
    "USRCLASS": USRCLASS_BRANCHES,
}


@dataclass(frozen=True)
class DetectionRule:
    pattern: str
    techniques: tuple[str, ...]
    description: str


DETECTION_RULES: tuple[DetectionRule, ...] = (
    DetectionRule("*\\classes\\clsid\\*", ("T1546/015",), "COM hijacking"),
    DetectionRule("*\\classes\\*\\shell\\*\\command", ("T1546/001",), "Default file association command"),
    DetectionRule("*\\microsoft\\active setup\\installed components\\*", ("T1547/014",), "Active Setup"),
    DetectionRule("*\\microsoft\\netsh*", ("T1546/007",), "Netsh helper DLL"),
    DetectionRule("*\\microsoft\\office\\*\\word\\options*", ("T1137/006",), "Office Word startup option"),
    DetectionRule("*\\microsoft\\office\\*\\word\\security\\trusted documents*", ("T1137/006",), "Office trusted document"),
    DetectionRule("*\\microsoft\\office\\*\\word\\security\\trusted locations*", ("T1137/006",), "Office trusted location"),
    DetectionRule("*\\microsoft\\office\\*\\common\\general*", ("T1137/006",), "Office template path"),
    DetectionRule("*\\microsoft\\office test\\special\\perf*", ("T1137/002",), "Office test persistence"),
    DetectionRule("*\\appcompatflags\\custom*", ("T1546/011",), "Application shim custom database"),
    DetectionRule("*\\appcompatflags\\installedsdb*", ("T1546/011",), "Installed shim database"),
    DetectionRule("*\\image file execution options*", ("T1546/008", "T1546/012"), "Image File Execution Options"),
    DetectionRule("*\\schedule\\taskcache\\tasks*", ("T1053/005",), "Scheduled task cache"),
    DetectionRule("*\\schedule\\taskcache\\tree*", ("T1053/005",), "Scheduled task tree"),
    DetectionRule("*\\silentprocessexit*", ("T1546/012",), "SilentProcessExit monitor"),
    DetectionRule("*\\currentversion\\windows*", ("T1547/001", "T1546/010"), "Windows load/run/AppInit configuration"),
    DetectionRule("*\\currentversion\\windows\\appinit_dlls", ("T1546/010",), "AppInit DLLs"),
    DetectionRule("*\\currentversion\\winlogon*", ("T1547/004",), "Winlogon helper"),
    DetectionRule("*\\currentversion\\run*", ("T1547/001",), "Run key"),
    DetectionRule("*\\policies\\explorer\\run*", ("T1547/001",), "Explorer policy Run key"),
    DetectionRule("*\\policies\\system\\shell*", ("T1547/001",), "Policy shell replacement"),
    DetectionRule("*\\startupapproved\\run*", ("T1547/001",), "StartupApproved Run key"),
    DetectionRule("*\\startupapproved\\startupfolder*", ("T1547/001",), "StartupApproved startup folder"),
    DetectionRule("*\\shellserviceobjectdelayload*", ("T1547/001",), "Shell service object delay load"),
    DetectionRule("*\\control panel\\desktop*", ("T1546/002",), "Screensaver configuration"),
    DetectionRule("*\\system\\scripts*", ("T1547/001",), "Group Policy script"),
    DetectionRule("*\\controlset001\\control\\print\\environments*", ("T1547/012",), "Print processor"),
    DetectionRule("*\\controlset001\\control\\print\\monitors*", ("T1547/010",), "Port monitor"),
    DetectionRule("*\\controlset001\\control\\lsa\\notification packages*", ("T1556/002",), "LSA notification package"),
    DetectionRule("*\\controlset001\\control\\lsa\\osconfig\\security packages*", ("T1547/002", "T1547/005"), "LSA OSConfig security package"),
    DetectionRule("*\\controlset001\\control\\lsa\\security packages*", ("T1547/002", "T1547/005"), "LSA security package"),
    DetectionRule("*\\controlset001\\control\\networkprovider\\order*", ("T1556/008",), "Network provider order"),
    DetectionRule("*\\controlset001\\control\\session manager\\appcertdlls*", ("T1546/009",), "AppCert DLL"),
    DetectionRule("*\\controlset001\\control\\session manager\\environment\\path", ("T1574/007",), "System PATH"),
    DetectionRule("*\\controlset001\\control\\session manager*", ("T1547/001", "T1546/009"), "Session Manager persistence"),
    DetectionRule("*\\controlset001\\services\\*\\networkprovider*", ("T1556/008",), "Service network provider"),
    DetectionRule("*\\controlset001\\services\\w32time\\timeproviders*", ("T1547/003",), "Time provider"),
    DetectionRule("*\\controlset001\\services*", ("T1543/003", "T1574/011"), "Windows service"),
    DetectionRule("*\\termservice\\parameters*", ("T1505/005",), "Terminal Services DLL"),
    DetectionRule("*\\terminal server\\wds\\rdpwd*", ("T1505/005",), "Terminal Services startup program"),
    DetectionRule("*\\terminal server\\winstations\\rdp-tcp*", ("T1505/005",), "Terminal Services initial program"),
    DetectionRule("*\\environment", ("T1037/001", "T1574/012"), "User environment persistence"),
    DetectionRule("*\\environment\\userinitmprlogonscript", ("T1037/001",), "User logon script"),
)


def normalize_registry_path(path: str) -> str:
    return path.replace("/", "\\").strip("\\").lower()


def match_detection_rules(key_path: str) -> tuple[DetectionRule, ...]:
    normalized = normalize_registry_path(key_path)
    matches: list[DetectionRule] = []

    for rule in DETECTION_RULES:
        pattern = normalize_registry_path(rule.pattern)
        if fnmatchcase(normalized, pattern):
            matches.append(rule)

    return tuple(matches)


def techniques_for_key_path(key_path: str) -> tuple[str, ...]:
    techniques: set[str] = set()

    for rule in match_detection_rules(key_path):
        techniques.update(rule.techniques)

    return tuple(sorted(techniques))
