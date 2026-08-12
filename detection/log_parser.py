#!/usr/bin/env python3
import re
import json
import argparse
from datetime import datetime


def parse_syslog_line(line, device_name, device_type):
    """
    Parse Cisco Packet Tracer syslog messages
    """
    # Remove leading *
    line = line.strip().lstrip("*").strip()

    event = {
        "TimeGenerated": "",
        "DeviceName": device_name,
        "DeviceType": device_type,
        "EventCategory": "Unknown",
        "Severity": "",
        "Action": "",
        "SourceIP": "",
        "DestinationIP": "",
        "Protocol": "",
        "Message": line
    }

    # Extract timestamp
    timestamp_match = re.search(
        r"([A-Z][a-z]{2}\s+\d{1,2},\s+\d{2}:\d{2}:\d{2})", line
    )
    if timestamp_match:
        timestamp = timestamp_match.group(1)
        try:
            event["TimeGenerated"] = datetime.strptime(f"{timestamp} {datetime.now().year}","%b %d, %H:%M:%S %Y").isoformat()
        except ValueError:
            event["TimeGenerated"] = timestamp

    # Cisco message format: %FACILITY-SEVERITY-MNEMONIC
    # NOTE 1: facility can contain underscores (e.g. PORT_SECURITY).
    # NOTE 2: this PT export sometimes drops the leading "%" entirely
    # (observed on SYS-5-CONFIG_I lines), so it's made optional here.
    severity_match = re.search(
        r"%?([A-Z_]+)-(\d)-([A-Z0-9_]+)", line
    )

    facility = ""
    mnemonic = ""

    if severity_match:
        facility = severity_match.group(1)
        severity = severity_match.group(2)
        mnemonic = severity_match.group(3)
        event["Severity"] = severity

        if "CONFIG" in mnemonic:
            event["EventCategory"] = "ConfigurationChange"
            event["Action"] = "CHANGE"
        elif facility in ("LINK", "LINEPROTO"):
            event["EventCategory"] = "InterfaceChange"
            # Do NOT substring-search "up"/"down" against the whole line —
            # the mnemonic "UPDOWN" itself contains the substring "down"
            # (u-p-d-o-w-n), which false-matches DOWN on every up event.
            # Every one of these messages ends with the actual reported
            # state as its last word ("...changed state to up" /
            # "...changed state to down" / "...administratively down") —
            # so just take the last word of the line instead of searching
            # the whole thing.
            last_word = line.strip().rstrip(".").split()[-1].lower()
            if last_word in ("up", "down"):
                event["Action"] = last_word.upper()
        elif facility == "PORT_SECURITY" or "PSECURE" in mnemonic or "VIOLATION" in mnemonic:
            event["EventCategory"] = "SecurityViolation"
            event["Action"] = "DENY"
        elif facility == "SEC" or "IPACCESSLOG" in mnemonic:
            event["EventCategory"] = "SecurityViolation"
            event["Action"] = "DENY"
        elif "LOGGINGHOST" in mnemonic:
            event["EventCategory"] = "LoggingConfiguration"
        else:
            event["EventCategory"] = mnemonic

    # Extract IP addresses if present
    ips = re.findall(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line
    )
    if len(ips) >= 1:
        event["SourceIP"] = ips[0]
    if len(ips) >= 2:
        event["DestinationIP"] = ips[1]

    return event


def parse_file(input_file, output_file, device_name, device_type):
    events = []
    last_raw_line = None

    with open(input_file, "r") as file:
        for raw_line in file:
            raw_line_stripped = raw_line.strip()
            if not raw_line_stripped:
                continue

            # Collapse consecutive exact duplicates — this PT export logs
            # every message twice (once via Console logging, once via
            # Monitor logging, per the "N message lines logged" counts
            # matching on both in `show logging`). Without this, event
            # counts would be inflated 2x relative to what actually
            # happened on the device.
            if raw_line_stripped == last_raw_line:
                last_raw_line = raw_line_stripped
                continue
            last_raw_line = raw_line_stripped

            event = parse_syslog_line(
                raw_line_stripped, device_name, device_type
            )
            events.append(event)

    with open(output_file, "w") as outfile:
        json.dump(
            events, outfile, indent=4
        )

    print(
        f"[+] Parsed {len(events)} events (duplicates collapsed)"
    )
    print(
        f"[+] Output saved to {output_file}"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Cisco Packet Tracer Syslog Parser"
    )
    parser.add_argument(
        "-i", "--input", required=True, help="Raw syslog file"
    )
    parser.add_argument(
        "-o", "--output", required=True, help="Output JSON file"
    )
    parser.add_argument(
        "-d", "--device", required=True, help="Hostname/device name"
    )
    parser.add_argument(
        "-t", "--type", default="Cisco Network Device", help="Device type"
    )

    args = parser.parse_args()

    parse_file(
        args.input, args.output, args.device, args.type
    )