import re

IOC_PATTERNS = {
    "Execution": [
        "cmd.exe",
        "command.com",
        "powershell",
        "rundll32",
        "regsvr32",
        "mshta"
    ],

    "Injection": [
        "VirtualAlloc",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "NtMapViewOfSection",
        "LoadLibraryA"
    ],

    "Persistence": [
        "CurrentVersion\\Run",
        "CurrentVersion\\RunOnce",
        "Startup",
        "schtasks"
    ],

    "Networking": [
        "URLDownloadToFile",
        "InternetOpen",
        "InternetConnect",
        "WinHttpOpen"
    ]
}


def analyze_iocs(strings_data):
    findings = {
        "Execution": [],
        "Injection": [],
        "Persistence": [],
        "Networking": []
    }

    all_strings = " ".join(strings_data)

    for category, indicators in IOC_PATTERNS.items():
        for indicator in indicators:
            if indicator.lower() in all_strings.lower():
                findings[category].append(indicator)

    total_iocs = sum(len(v) for v in findings.values())

    return {
        "findings": findings,
        "total": total_iocs
    }