"""Direct, certificate-verified KEV downloads with bounded JSON parsing."""

import gc
import json
import socket
import ssl
import time

HOST = "www.cisa.gov"
PATH = "/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FIELDS = ("cveID", "vendorProject", "product", "vulnerabilityName",
          "dateAdded", "shortDescription", "requiredAction", "dueDate",
          "knownRansomwareCampaignUse")


def date_string(seconds):
    parts = time.gmtime(seconds)
    return "%04d-%02d-%02d" % parts[:3]


def recent_entries(stream, today, yesterday):
    """Parse one vulnerability at a time, including escaped/nested JSON."""
    marker = b'"vulnerabilities"'
    prefix = b""
    started = False
    record = bytearray()
    depth = 0
    quoted = False
    escaped = False
    total = 0
    found_end = False
    results = []
    while True:
        chunk = stream.read(2048)
        if not chunk:
            break
        total += len(chunk)
        if total > 4 * 1024 * 1024:
            raise ValueError("CISA feed exceeds download limit")
        if not started:
            prefix += chunk
            index = prefix.find(marker)
            if index < 0:
                prefix = prefix[-len(marker):]
                continue
            index = prefix.find(b"[", index + len(marker))
            if index < 0:
                # Header is short, but the array delimiter can cross a read.
                continue
            chunk = prefix[index + 1:]
            prefix = b""
            started = True
        for char in chunk:
            if depth == 0:
                if char == 93:
                    found_end = True
                    break
                if char in (9, 10, 13, 32, 44):
                    continue
                if char != 123:
                    raise ValueError("Invalid KEV array")
                depth = 1
                record = bytearray(b"{")
                continue
            record.append(char)
            if len(record) > 32768:
                raise ValueError("Oversized KEV record")
            if quoted:
                if escaped:
                    escaped = False
                elif char == 92:
                    escaped = True
                elif char == 34:
                    quoted = False
            elif char == 34:
                quoted = True
            elif char == 123:
                depth += 1
            elif char == 125:
                depth -= 1
                if depth == 0:
                    entry = json.loads(record)
                    if entry.get("dateAdded") in (today, yesterday):
                        results.append({key: entry.get(key, "") for key in FIELDS})
                    record = bytearray()
        if found_end:
            break
    if not started or not found_end:
        raise ValueError("Incomplete CISA feed")
    results.sort(key=lambda entry: (entry["dateAdded"], entry["cveID"]), reverse=True)
    return results


def fetch_recent():
    now = time.time()
    if time.gmtime(now)[0] < 2025:
        raise ValueError("Clock needs synchronization")
    raw = None
    secure = None
    try:
        address = socket.getaddrinfo(HOST, 443, 0, socket.SOCK_STREAM)[0][-1]
        raw = socket.socket()
        raw.settimeout(20)
        raw.connect(address)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile="/data/kev-ca.pem")
        secure = context.wrap_socket(raw, server_hostname=HOST)
        request = ("GET %s HTTP/1.0\r\nHost: %s\r\n"
                   "Accept: application/json\r\nAccept-Encoding: identity\r\n"
                   "Connection: close\r\n\r\n") % (PATH, HOST)
        payload = request.encode()
        sent = 0
        while sent < len(payload):
            written = secure.write(payload[sent:])
            if not written:
                raise OSError("HTTPS write failed")
            sent += written
        status = secure.readline().split()
        if len(status) < 2 or status[1] != b"200":
            raise OSError("CISA HTTP status " + str(status))
        header_bytes = 0
        server_time = None
        while True:
            line = secure.readline()
            header_bytes += len(line)
            if not line or header_bytes > 16384:
                raise ValueError("Invalid HTTP headers")
            if not line.strip():
                break
            if line.lower().startswith(b"date:"):
                parts = line.decode().split()
                # HTTP Date is authenticated by the already verified TLS channel.
                months = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
                          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
                if len(parts) == 7 and parts[-1] == "GMT":
                    hour, minute, second = [int(value) for value in parts[5].split(":")]
                    server_time = time.mktime((int(parts[4]), months.index(parts[3]) + 1,
                                               int(parts[2]), hour, minute, second, 0, 0, 0))
            if line.lower().startswith(b"transfer-encoding:"):
                if b"identity" not in line.lower():
                    raise ValueError("Unsupported HTTP transfer encoding")
            if line.lower().startswith(b"content-encoding:"):
                if b"identity" not in line.lower():
                    raise ValueError("Unsupported HTTP compression")
        if server_time is None:
            raise ValueError("CISA response is missing a valid Date header")
        now = server_time
        import machine
        clock = time.gmtime(now)
        machine.RTC().datetime((clock[0], clock[1], clock[2], clock[6],
                                clock[3], clock[4], clock[5], 0))
        today = date_string(now)
        yesterday = date_string(now - 86400)
        print("KEV downloading catalog for", yesterday, today)
        entries = recent_entries(secure, today, yesterday)
        return {"checked": now, "today": today, "yesterday": yesterday, "entries": entries}
    finally:
        if secure is not None:
            secure.close()
        if raw is not None:
            raw.close()
        gc.collect()
