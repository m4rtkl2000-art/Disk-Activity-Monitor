# 🛡️ Disk Activity Monitor & Threat Detector

**Disk Activity Monitor** is a lightweight security tool for Windows that monitors file access activity of running processes in **real-time**.

It includes built-in **Threat Intelligence analysis** designed to detect behaviors commonly associated with **Ransomware** and **Malware**, such as abnormal file encryption, suspicious process lineage, and persistence mechanisms.

---

## ✨ Features

- 🔍 **Real-time Disk Monitoring**  
  Monitor which processes are actively reading from or writing to files across all drives.

- 🌳 **Process Genealogy Analysis**  
  Analyze parent-child process relationships to detect anomalies  
  (e.g., `lsass.exe` not launched by `wininit.exe`).

- 📉 **Entropy Analysis**  
  Calculate file entropy to identify potential encryption behavior  
  (useful for early ransomware detection).

- 🔐 **Registry Persistence Detection**  
  Inspect common startup and persistence registry locations used by malware.

- 🚀 **VirusTotal Integration**  
  Instantly submit file hashes (SHA-256) to VirusTotal with a single click.

- 📸 **Baseline Snapshot System**  
  Capture a “clean” system baseline and compare it against current activity  
  to detect newly spawned or suspicious processes.

---

## 🛠️ Installation

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/disk-activity-monitor.git
cd disk-activity-monitor
```

### 2️⃣ Install Required Libraries
```bash
pip install imgui-bundle psutil
```

### 3️⃣ Run the Application
```bash
python main.py
```

---

## 🖥️ Usage

1. Select Drive
Choose the drive to monitor or select All Drives.
2. Set Baseline
Capture the current system state.
Recommended when the system is in a clean and idle state.
3. Scan
Start scanning for abnormal disk and process activity.
4. Threat Report Window
If suspicious activity is detected, a report window will appear with options to:
  - ✅ Verify — Check the file hash via VirusTotal
  - 📂 Reveal — Open the file’s directory
  - ❌ Terminate — Immediately terminate the suspicious process

---

## 📂 Project Structure
```bash
disk-activity-monitor/
│
├── main.py           # Main UI and application state management
├── disk_scanner.py   # Core scanning engine, entropy & hash calculation
├── snapshot.py       # Baseline snapshot and comparison system
├── logs.py           # Scan report and logging utilities
├── ui.py             # ImGui UI components
└── logs/             # Scan result logs
```

---

## ⚠️ Disclaimer
This software is intended for educational and preliminary security analysis purposes only.
It is not a replacement for a full-featured antivirus or endpoint protection solution.

The developer assumes no responsibility for any damage or data loss resulting from the use of this software.
