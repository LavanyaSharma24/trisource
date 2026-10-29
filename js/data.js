/* data.js — case data & ATT&CK reference.
   The victim01 values are the REAL evidence produced by the project's three
   analysis tracks (detection, disk, memory). */

const TECHNIQUES = {
  "T1059.001": { name: "PowerShell Command Execution", tactic: "Execution" },
  "T1047":     { name: "WMI Reconnaissance",           tactic: "Discovery" },
  "T1053.005": { name: "Scheduled Task (persistence)", tactic: "Persistence" },
  "T1547.001": { name: "Registry Run Key (persistence)", tactic: "Persistence" },
  "T1112":     { name: "Modify Registry",              tactic: "Defense Evasion" },
  "T1016":     { name: "Network Config Discovery",     tactic: "Discovery" },
  "T1082":     { name: "System Information Discovery",  tactic: "Discovery" },
  "T1057":     { name: "Process Discovery (tasklist)", tactic: "Discovery" },
  "T1033":     { name: "System Owner/User Discovery",  tactic: "Discovery" },
  /* Techniques covered by the extended rule set (rules.json) — not in victim01. */
  "T1003":     { name: "OS Credential Dumping",        tactic: "Credential Access" },
  "T1562.001": { name: "Disable or Modify Tools (Defender)", tactic: "Defense Evasion" },
  "T1055":     { name: "Process Injection",            tactic: "Defense Evasion" },
  "T1136":     { name: "Create Account",               tactic: "Persistence" },
  "T1105":     { name: "Ingress Tool Transfer",        tactic: "Command and Control" }
};

/* The demo case = the real Atomic Red Team run on victim01 (2026-10-06, UTC). */
const DEMO_EVENTS = [
  { ts: "13:19:02", img: "explorer.exe",   cmd: "C:\\Windows\\explorer.exe" },
  { ts: "13:21:19", img: "powershell.exe", cmd: "powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACcASABlAGwAbABvACcA" },
  { ts: "13:24:45", img: "cmd.exe",        cmd: "wmic useraccount list full" },
  { ts: "13:25:29", img: "schtasks.exe",   cmd: "schtasks /create /tn T1053_005_OnLogon /tr \"cmd.exe /c calc.exe\" /sc onlogon" },
  { ts: "13:26:48", img: "reg.exe",        cmd: "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v \"Atomic Red Team\" /d C:\\Path\\AtomicRedTeam.exe /f" },
  { ts: "13:27:29", img: "reg.exe",        cmd: "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced /v HideFileExt /t REG_DWORD /d 1 /f" },
  { ts: "13:28:46", img: "cmd.exe",        cmd: "ipconfig /all & arp -a & netsh interface show interface & nbtstat -n" },
  { ts: "13:40:36", img: "cmd.exe",        cmd: "whoami & quser & qwinsta" },
  { ts: "13:40:45", img: "systeminfo.exe", cmd: "systeminfo" },
  { ts: "13:40:52", img: "tasklist.exe",   cmd: "tasklist" }
];

/* Multi-source correlation for the demo case, from the real Disk & Memory tracks.
   Y = recovered, N = not present (a red flag), "-" = not applicable. */
const CASE_SOURCES = {
  "T1059.001": { prefetch:"Y", registry:"-", memory:"N", ev:{ prefetch:"POWERSHELL.EXE prefetch, run time 13:21:20 (run count 13)", registry:"n/a — no persistence written", memory:"not recovered — image unparseable / process had exited" } },
  "T1053.005": { prefetch:"Y", registry:"Y", memory:"N", ev:{ prefetch:"SCHTASKS.EXE ×2 @ 13:25:29", registry:"TaskCache: T1053_005_OnLogon / OnStartup, action cmd.exe /c calc.exe, author analyst", memory:"not recovered" } },
  "T1547.001": { prefetch:"Y", registry:"Y", memory:"N", ev:{ prefetch:"REG.EXE @ 13:26:48", registry:"HKCU\\...\\Run value 'Atomic Red Team' still present at collection (7 days later)", memory:"not recovered" } },
  "T1112":     { prefetch:"Y", registry:"N", memory:"N", ev:{ prefetch:"CMD.EXE → REG.EXE @ 13:27:29 — the ONLY proof this ran", registry:"NO trace — value equalled the existing default, so no change was recorded", memory:"not recovered" } },
  "T1016":     { prefetch:"Y", registry:"Y", memory:"N", ev:{ prefetch:"IPCONFIG, NETSH, ARP, NBTSTAT @ 13:28:46-47 (each run once)", registry:"side-effect keys (RFC1156Agent, Tracing\\MPRAPI) touched 13:28:47", memory:"not recovered" } },
  "T1082":     { prefetch:"Y", registry:"-", memory:"N", ev:{ prefetch:"SYSTEMINFO.EXE @ 13:40:45 (run count 1)", registry:"n/a", memory:"not recovered" } },
  "T1057":     { prefetch:"Y", registry:"-", memory:"N", ev:{ prefetch:"TASKLIST.EXE @ 13:40:52 (run count 1)", registry:"n/a", memory:"not recovered" } },
  "T1033":     { prefetch:"Y", registry:"-", memory:"N", ev:{ prefetch:"WHOAMI/QUSER/QWINSTA @ 13:40:36; no WMIC.EXE (corroborates partial failure)", registry:"n/a", memory:"not recovered" } }
};

const MX_ORDER = ["T1059.001","T1053.005","T1547.001","T1112","T1016","T1082","T1057","T1033"];
