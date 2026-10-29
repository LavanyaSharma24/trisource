"""Tests for the ingestion backend (backend/).

    pip install -r requirements-dev.txt
    pytest

The parser is tested on record XML exactly as python-evtx emits it (copied from
a real Sysmon log), so no binary fixture is needed. To also run the end-to-end
upload test against a real file, point TRISOURCE_TEST_EVTX at a Sysmon .evtx,
e.g. one from https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES .
"""
import io
import os

import pytest
from fastapi.testclient import TestClient

from backend.app import app
from backend.evtx_parser import event_from_xml, is_evtx

client = TestClient(app)


def record(provider="Microsoft-Windows-Sysmon", event_id=1, data=None, system_time="2019-08-30 12:54:08.873791+00:00"):
    """Build record XML in the shape python-evtx's Record.xml() produces."""
    data = {"UtcTime": "2019-08-30 12:54:08.331", "Image": r"C:\Windows\System32\rundll32.exe",
            "CommandLine": r"rundll32 C:\windows\system32\comsvcs.dll, MiniDump 4868 C:\x.bin full"} if data is None else data
    fields = "\n".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
    return f"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>
<Provider Name="{provider}" Guid="{{5770385f-c22a-43e0-bf4c-06f5698ffbd9}}"></Provider>
<EventID Qualifiers="">{event_id}</EventID>
<TimeCreated SystemTime="{system_time}"></TimeCreated>
<EventRecordID>32154</EventRecordID>
<Channel>Microsoft-Windows-Sysmon/Operational</Channel>
</System>
<EventData><Data Name="RuleName"></Data>
{fields}
<Data Name="Description">Microsoft &#174; Windows host process</Data>
</EventData></Event>"""


# ---- parser ----------------------------------------------------------------

def test_sysmon_process_create_is_extracted():
    kind, ev = event_from_xml(record())
    assert kind == "event"
    assert ev == {"ts": "2019-08-30 12:54:08.331",
                  "image": r"C:\Windows\System32\rundll32.exe",
                  "commandline": r"rundll32 C:\windows\system32\comsvcs.dll, MiniDump 4868 C:\x.bin full",
                  "record_id": 32154}


def test_other_sysmon_event_ids_are_classified_not_returned():
    assert event_from_xml(record(event_id=3)) == ("other_event_id", None)   # network connection


def test_non_sysmon_records_are_classified_not_returned():
    assert event_from_xml(record(provider="Microsoft-Windows-Security-Auditing", event_id=4688)) == ("non_sysmon", None)


def test_falls_back_to_timecreated_when_utctime_missing():
    _, ev = event_from_xml(record(data={"Image": "C:\\x.exe", "CommandLine": "x.exe"}))
    assert ev["ts"] == "2019-08-30 12:54:08.873791"


def test_entity_expansion_is_refused():
    """Log content is untrusted: defusedxml must reject entity declarations."""
    bomb = '<!DOCTYPE x [<!ENTITY a "aaaa">]><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">&a;</Event>'
    with pytest.raises(Exception):
        event_from_xml(bomb)


def test_magic_header_check():
    assert is_evtx(b"ElfFile\x00rest")
    assert not is_evtx(b"Timestamp,Image,CommandLine\n")


# ---- API -------------------------------------------------------------------

def test_health():
    body = client.get("/api/health").json()
    assert body["status"] == "ok" and body["parser"] == "python-evtx"


def test_rejects_non_evtx_upload():
    r = client.post("/api/parse/evtx", files={"file": ("log.csv", io.BytesIO(b"Timestamp,Image,CommandLine\n"))})
    assert r.status_code == 400 and "ElfFile" in r.json()["detail"]


def test_rejects_empty_upload():
    r = client.post("/api/parse/evtx", files={"file": ("x.evtx", io.BytesIO(b""))})
    assert r.status_code == 400


def test_corrupt_evtx_is_a_clean_422_not_a_crash():
    r = client.post("/api/parse/evtx", files={"file": ("x.evtx", io.BytesIO(b"ElfFile\x00" + b"\x00" * 64))})
    assert r.status_code == 422


def test_serves_frontend_but_not_backend_source():
    assert client.get("/").status_code == 200
    assert client.get("/rules.json").json()["rules"]
    assert client.get("/js/app.js").status_code == 200
    assert client.get("/backend/app.py").status_code == 404
    assert client.get("/requirements.txt").status_code == 404


@pytest.mark.skipif(not os.getenv("TRISOURCE_TEST_EVTX"), reason="set TRISOURCE_TEST_EVTX=path/to/sysmon.evtx")
def test_real_evtx_end_to_end():
    with open(os.environ["TRISOURCE_TEST_EVTX"], "rb") as fh:
        r = client.post("/api/parse/evtx", files={"file": ("real.evtx", fh)})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total_records"] > 0
    assert body["sysmon_process_events"] == len(body["events"])
    for ev in body["events"]:
        assert set(ev) == {"ts", "image", "commandline", "record_id"}
    assert [e["ts"] for e in body["events"]] == sorted(e["ts"] for e in body["events"])
