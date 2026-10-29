"""evtx_parser.py — Stage 1 for real logs: Sysmon .evtx -> {ts, image, commandline}.

This module is deliberately free of web-framework code so the parsing logic can
be read, tested and reused on its own (e.g. from a notebook or CLI).

What it extracts
----------------
Only Sysmon *Process Create* records (provider Microsoft-Windows-Sysmon,
Event ID 1) — the same event type the front-end's rule engine matches on. Every
other record is counted, not silently dropped, so the analyst can see what the
file contained:

    {"ts": "2019-08-30 12:54:07.823",         # Sysmon UtcTime (UTC), verbatim
     "image": "C:\\Windows\\System32\\cmd.exe",  # full path as Sysmon logged it
     "commandline": "cmd.exe /c whoami",
     "record_id": 32151}                       # EventRecordID — trace back to source

How
---
python-evtx decodes each binary-XML record into an XML string; we parse that
with defusedxml (the file is untrusted input) and read the System and EventData
fields by name.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from defusedxml import ElementTree as ET
from Evtx.Evtx import Evtx

EVTX_MAGIC = b"ElfFile\x00"           # first 8 bytes of every .evtx file header
SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"
SYSMON_PROCESS_CREATE = 1
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


class NotEvtxError(ValueError):
    """The uploaded bytes are not a Windows event log."""


class CorruptEvtxError(ValueError):
    """It claims to be EVTX, but the file header is unusable."""


@dataclass
class ParseResult:
    events: list[dict] = field(default_factory=list)
    total_records: int = 0
    skipped_non_sysmon: int = 0       # e.g. a Security.evtx or System.evtx record
    skipped_other_event_ids: int = 0  # Sysmon, but not Event ID 1 (network, file, ...)
    malformed_records: int = 0        # record could not be decoded / parsed
    truncated: bool = False           # stopped at max_events
    warnings: list[str] = field(default_factory=list)  # integrity notes for the analyst

    def summary(self) -> dict:
        return {
            "total_records": self.total_records,
            "sysmon_process_events": len(self.events),
            "skipped_non_sysmon": self.skipped_non_sysmon,
            "skipped_other_event_ids": self.skipped_other_event_ids,
            "malformed_records": self.malformed_records,
            "truncated": self.truncated,
            "warnings": self.warnings,
        }


def is_evtx(head: bytes) -> bool:
    return head[: len(EVTX_MAGIC)] == EVTX_MAGIC


def event_from_xml(xml: str) -> tuple[str, dict | None]:
    """Classify one record's XML. Returns (kind, event) where kind is one of
    "event" | "non_sysmon" | "other_event_id"; event is set only for "event"."""
    root = ET.fromstring(xml)
    system = root.find("e:System", NS)
    provider = system.find("e:Provider", NS)
    if provider is None or provider.get("Name") != SYSMON_PROVIDER:
        return "non_sysmon", None
    if int((system.findtext("e:EventID", default="", namespaces=NS) or "-1").strip()) != SYSMON_PROCESS_CREATE:
        return "other_event_id", None

    data = {d.get("Name"): (d.text or "") for d in root.iterfind("e:EventData/e:Data", NS)}
    # Prefer Sysmon's own UtcTime (when the process started); fall back to the
    # time the record was written.
    ts = data.get("UtcTime", "").strip()
    if not ts:
        created = system.find("e:TimeCreated", NS)
        ts = (created.get("SystemTime", "") if created is not None else "").split("+")[0]
    record_id = system.findtext("e:EventRecordID", default="", namespaces=NS).strip()
    return "event", {
        "ts": ts,
        "image": data.get("Image", "").strip(),
        "commandline": data.get("CommandLine", "").strip(),
        "record_id": int(record_id) if record_id.isdigit() else None,
    }


def parse_evtx_file(path: str, max_events: int = 20000) -> ParseResult:
    """Parse a .evtx file on disk. python-evtx memory-maps the file, so it needs
    a real path rather than a stream. Raises NotEvtxError for non-EVTX input."""
    with open(path, "rb") as fh:
        if not is_evtx(fh.read(len(EVTX_MAGIC))):
            raise NotEvtxError("not a Windows event log (.evtx): missing 'ElfFile' header")

    result = ParseResult()
    with Evtx(path) as log:
        # Integrity: a wrong version / chunk size means we cannot trust the
        # layout at all -> refuse. A bad checksum or "dirty" flag is common for
        # logs copied off a live host, so parse anyway but tell the analyst.
        header = log.get_file_header()
        if header.major_version() != 3 or header.header_chunk_size() != 0x1000:
            raise CorruptEvtxError(f"unsupported or corrupt EVTX header (version {header.major_version()}."
                                   f"{header.minor_version()}, header size {header.header_chunk_size()})")
        if header.checksum() != header.calculate_checksum():
            result.warnings.append("file header checksum mismatch - file may be truncated or copied while in use")
        if header.is_dirty():
            result.warnings.append("log is marked dirty (not cleanly closed) - the newest records may be missing")

        for record in log.records():
            result.total_records += 1
            try:
                kind, event = event_from_xml(record.xml())
            except Exception:  # one corrupt record must not abort the whole file
                result.malformed_records += 1
                continue
            if kind == "non_sysmon":
                result.skipped_non_sysmon += 1
            elif kind == "other_event_id":
                result.skipped_other_event_ids += 1
            elif len(result.events) >= max_events:
                result.truncated = True
                break
            else:
                result.events.append(event)

    # Chronological order for the timeline. UtcTime ("YYYY-MM-DD HH:MM:SS.mmm")
    # sorts correctly as text; the sort is stable, so ties keep record order.
    result.events.sort(key=lambda e: e["ts"])
    return result
