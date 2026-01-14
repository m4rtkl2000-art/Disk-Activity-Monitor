import os
import re
import psutil
from collections import defaultdict
import hashlib
import math

def calculate_entropy(file_path):
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = data.count(x) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        return entropy
    except:
        return 0

def check_registry_persistence():
    import winreg
    paths = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run")
    ]
    persistence_items = []
    for hkey, path in paths:
        try:
            with winreg.OpenKey(hkey, path) as key:
                for i in range(winreg.QueryInfoKey(key)[1]):
                    name, value, _ = winreg.EnumValue(key, i)
                    persistence_items.append({"name": name, "path": value})
        except: pass
    return persistence_items

def get_file_hash(file_path):
    """คำนวณค่า SHA-256 ของไฟล์"""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            # อ่านไฟล์ทีละก้อน (Chunk) เพื่อไม่ให้กิน RAM กรณีไฟล์ใหญ่
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except:
        return None # กรณีเข้าถึงไฟล์ไม่ได้ (เช่น ถูกระบบล็อค)

def scan_disk_usage(selected_drive=None):
    drive_logs = defaultdict(list)
    unique_programs = set()
    drives = ("C:\\", "E:\\", "F:\\", "G:\\") if selected_drive is None else (selected_drive,)

    for p in psutil.process_iter(['pid', 'name', 'ppid']):
        try:
            # ดึงข้อมูล Parent
            ppid = p.info['ppid']
            try:
                parent_name = psutil.Process(ppid).name()
            except:
                parent_name = "Unknown/System"

            for f in p.open_files():
                for d in drives:
                    if f.path.startswith(d):
                        drive_logs[d].append({
                            "name": p.info['name'],
                            "pid": p.pid,
                            "parent_name": parent_name, # เก็บชื่อตัวแม่
                            "parent_pid": ppid,
                            "path": f.path
                        })
                        unique_programs.add(p.info['name'])
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
    return drive_logs, sorted(unique_programs), any(len(v) > 0 for v in drive_logs.values())

def refresh_drives():
    import psutil
    # ดึงรายชื่อไดรฟ์จริงในเครื่อง
    found_drives = [p.mountpoint for p in psutil.disk_partitions()]
    # คืนค่าเป็น list ที่มี "All Drives" อยู่หน้าสุด
    print(f"Found drives: {found_drives}")
    return ["All Drives"] + found_drives

def kill_process_by_pid(pid):
    try:
        process = psutil.Process(pid)
        process.terminate()
        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False
    
def is_suspicious(path: str, name: str):
    """
    Advanced Threat Detection Logic
    Accuracy Target: High Fidelity (Low False Positive)
    
    return:
        suspicious (bool): True if risk_score >= threshold
        risk_score (int): 0-100+
        reasons (list): Detailed forensic reasons
    """
    
    reasons = []
    risk_score = 0
    
    # Normalize inputs
    path_norm = os.path.normpath(path).lower()
    name_lower = name.lower()
    
    # ---------------------------------------------------------
    # 0. IGNORE SAFE EXTENSIONS (Whitelist)
    # ส่วนที่เพิ่ม: ข้ามไฟล์ Font, รูปภาพ, และไฟล์ข้อมูลทั่วไป
    # ---------------------------------------------------------
    # รายชื่อนามสกุลไฟล์ที่ "ไม่ใช่โปรแกรม" และปลอดภัยที่จะข้าม
    safe_extensions = (
        '.ttf', '.otf', '.fon', '.ttc',   # Font files
        '.txt', '.log', '.ini',   # Text/Config
        '.png', '.jpg', '.jpeg', '.bmp', '.ico', # Images
        '.xml', '.json', '.dat', '.db', '.tmp', # Data files
        '.mp3', '.mp4', '.wav'    # Media
    )
    
    # เช็คว่า Path ของไฟล์ ลงท้ายด้วยนามสกุลเหล่านี้หรือไม่
    if path_norm.endswith(safe_extensions):
        return False, 0, []  # คืนค่าว่าไม่น่าสงสัยทันที
    
    # ดึงนามสกุลไฟล์ออกมาเช็ค
    _, ext = os.path.splitext(name_lower)
    
    # ---------------------------------------------------------
    # 1. CRITICAL: System File Masquerading (Imposters)
    # เทคนิคนี้แม่นยำ 99.9% - โปรแกรมปกติจะไม่ตั้งชื่อทับไฟล์ระบบนอกโฟลเดอร์ระบบ
    # ---------------------------------------------------------
    
    # Dictionary จับคู่ชื่อไฟล์ระบบ กับ โฟลเดอร์ที่ควรอยู่
    # หมายเหตุ: syswow64 จำเป็นสำหรับ Windows 64bit ที่รันโปรแกรม 32bit
    system_files_map = {
        "svchost.exe":  ["windows\\system32", "windows\\syswow64"],
        "lsass.exe":    ["windows\\system32"],
        "csrss.exe":    ["windows\\system32"],
        "smss.exe":     ["windows\\system32"],
        "services.exe": ["windows\\system32"],
        "wininit.exe":  ["windows\\system32"],
        "lsm.exe":      ["windows\\system32"],
        "winlogon.exe": ["windows\\system32"],
        "explorer.exe": ["windows"], # explorer อยู่ที่ C:\Windows
        "taskmgr.exe":  ["windows\\system32"],
        "spoolsv.exe":  ["windows\\system32"],
        "conhost.exe":  ["windows\\system32"],
        "ctfmon.exe":   ["windows\\system32", "windows\\syswow64"]
    }

    if name_lower in system_files_map:
        allowed_paths = system_files_map[name_lower]
        # ตรวจสอบว่า Path ปัจจุบัน มีส่วนประกอบของ Allowed Path หรือไม่
        is_legit_location = any(allow in path_norm for allow in allowed_paths)
        
        if not is_legit_location:
            risk_score += 100
            reasons.append(f"CRITICAL: System file imposter! '{name}' running from '{path}'")

    # ---------------------------------------------------------
    # 2. CRITICAL: Double Extension / Spoofing
    # ---------------------------------------------------------
    # เช่น invoice.pdf.exe, image.jpg.scr (หลอกว่าเป็นไฟล์เอกสาร)
    # Regex: หาชื่อไฟล์ที่มีจุด ตามด้วยนามสกุลหลอก (doc, pdf, etc) แล้วจบด้วย exe/scr/bat
    double_ext_pattern = r".+\.(doc|docx|xls|xlsx|pdf|txt|jpg|png|ppt|pptx)\.(exe|scr|com|bat|cmd|vbs|js)$"
    
    if re.search(double_ext_pattern, name_lower):
        risk_score += 80
        reasons.append("High Risk: Double extension spoofing detected")

    # ---------------------------------------------------------
    # 3. HIGH: Suspicious Execution Locations
    # ---------------------------------------------------------
    # โฟลเดอร์เหล่านี้ โปรแกรมปกติไม่ควรไปรันอยู่ (นอกจาก Installer ชั่วคราว)
    
    suspicious_dirs = {
        "\\appdata\\local\\temp\\": 40,   # Malware droppers often run here
        "\\users\\public\\": 50,          # Common hiding spot for RATs
        "\\windows\\fonts\\": 80,         # Very rare for exe, used by exploits
        "\\windows\\help\\": 70,          # Legacy hiding spot
        "\\windows\\debug\\": 70,
        "$recycle.bin": 90,               # Running from trash? Definitely malware
        "\\intel\\logs\\": 40             # Common hiding spot
    }

    for susp_path, score in suspicious_dirs.items():
        if susp_path in path_norm:
            # ข้อยกเว้น: บางโปรแกรมติดตั้ง (Setup/Install) อาจรันใน Temp
            # ถ้าชื่อไฟล์มีคำว่า setup, install อาจลดคะแนนลง หรือปล่อยผ่าน
            if "install" in name_lower or "setup" in name_lower or "update" in name_lower:
                risk_score += 10 
                reasons.append(f"Installer running in temp: {susp_path}")
            else:
                risk_score += score
                reasons.append(f"Suspicious execution directory: {susp_path}")

    # ---------------------------------------------------------
    # 4. MEDIUM: Known Threat Names (Exact & Regex)
    # ---------------------------------------------------------
    
    # Exact Match (รายชื่อมัลแวร์ยอดฮิต)
    blacklist_names = {
        # ----------------------------
        # Crypto Miners
        # ----------------------------
        "xmrig.exe", "xmrig64.exe", "xmrig32.exe",
        "minerd.exe", "cpuminer.exe", "ccminer.exe",
        "ethminer.exe", "nanominer.exe", "lolminer.exe",
        "trex.exe", "teamredminer.exe", "nbminer.exe",
        "bzminer.exe", "phoenixminer.exe", "claymore.exe",
        "cryptominer.exe", "coinminer.exe",

        # ----------------------------
        # RAT / Backdoor
        # ----------------------------
        "darkme.exe", "nanocore.exe", "nanocoreclient.exe",
        "remcos.exe", "remcosclient.exe",
        "njrat.exe", "njratlime.exe",
        "asyncrat.exe", "quasar.exe",
        "orcrat.exe", "poisonivy.exe",
        "adwind.exe", "jrat.exe",
        "agenttesla.exe", "backdoor.exe",
        "rat.exe", "server.exe", "client.exe",

        # ----------------------------
        # Info Stealers
        # ----------------------------
        "redline.exe", "redlinestealer.exe",
        "raccoon.exe", "raccoonstealer.exe",
        "vidar.exe", "vidarstealer.exe",
        "azorult.exe", "azorult2.exe",
        "formbook.exe",
        "loki.exe", "lokibot.exe",
        "metastealer.exe",
        "pandora.exe", "ficker.exe",
        "stealer.exe", "passwordstealer.exe",
        "browsergrabber.exe",

        # ----------------------------
        # Ransomware
        # ----------------------------
        "wannacry.exe", "wannacrypt.exe",
        "lockbit.exe", "lockbit3.exe",
        "conti.exe", "ryuk.exe",
        "revil.exe", "sodinokibi.exe",
        "maze.exe", "clop.exe",
        "akira.exe", "blackcat.exe",
        "alphv.exe", "medusa.exe",
        "play.exe", "royal.exe",

        # ----------------------------
        # Loaders / Droppers
        # ----------------------------
        "loader.exe", "dropper.exe",
        "payload.exe", "stub.exe",
        "stage.exe", "runpayload.exe",
        "inject.exe", "injector.exe",
        "shellcode.exe", "reflective.exe",
        "packer.exe", "crypter.exe",

        # ----------------------------
        # Malware Framework / Botnet
        # ----------------------------
        "emotet.exe", "trickbot.exe",
        "qakbot.exe", "pikabot.exe",
        "icedid.exe", "dridex.exe",
        "gozi.exe", "ursnif.exe",
        "zeus.exe", "zloader.exe",

        # ----------------------------
        # Dual-use / Context dependent tools
        # ----------------------------
        "mimikatz.exe", "psexec.exe",
        "procdump.exe", "procmon.exe",
        "tcpview.exe", "nmap.exe",
        "masscan.exe", "netscan.exe",
        "powersploit.exe", "cobaltstrike.exe",
        "beacon.exe",

        # ----------------------------
        # Fake system / Common disguises
        # ----------------------------
        "svch0st.exe", "svhost.exe",
        "lsasss.exe", "csrsss.exe",
        "winlogon.exe.exe", "services32.exe",
        "system.exe", "system32.exe",
        "taskmngr.exe", "explorrer.exe",
        "conhost32.exe",

        # ----------------------------
        # Generic / Suspicious names
        # ----------------------------
        "update.exe", "updater.exe",
        "windowsupdate.exe", "security.exe",
        "antivirus.exe", "patch.exe",
        "fix.exe", "helper.exe",
        "runtime.exe", "autorun.exe",
        "silent.exe", "hidden.exe",
        "temp.exe", "tmp.exe",
        "hack.exe", "crack.exe",
        "kms.exe", "kmsauto.exe",
    }
    
    if name_lower in blacklist_names:
        risk_score += 70
        reasons.append("Blacklisted threat name")

    # Pattern Match (Miner/HackTool keywords)
    # ระวัง: ต้องเช็คให้ดีไม่ให้ false positive กับ "Minecraft" (miner)
    if re.search(r"^(aa)?miner(d)?\.exe$", name_lower): # minerd.exe, miner.exe
        risk_score += 60
        reasons.append("Cryptominer keyword detected")
        
    if "keylog" in name_lower:
        risk_score += 60
        reasons.append("Keylogger keyword detected")

    # ---------------------------------------------------------
    # 5. MEDIUM: Typosquatting (Visual Spoofing)
    # ---------------------------------------------------------
    # ชื่อที่ตั้งใจเขียนผิดให้เหมือน System File
    
    typo_patterns = [
        r"svch0st\.exe",  # Zero instead of 'o'
        r"scvhost\.exe",  # Swapped letters
        r"1sass\.exe",    # One instead of 'l'
        r"lsasss\.exe",   # Extra 's'
        r"winiogon\.exe", # 'i' instead of 'l'
        r"expIorer\.exe", # Capital 'i' instead of 'l' (looks same in sans-serif)
    ]
    
    for pat in typo_patterns:
        if re.search(pat, name_lower):
            risk_score += 85
            reasons.append("Visual spoofing (Typosquatting) of system file")
            break

    # ---------------------------------------------------------
    # 6. LOW: Single Letter Executables
    # ---------------------------------------------------------
    # ไฟล์ชื่อ a.exe, 1.exe มักจะเป็น Test virus หรือ Dropper
    if re.match(r"^[a-z0-9]\.exe$", name_lower):
        # เช็คเพิ่มว่าไม่ได้อยู่ใน Program Files (ถ้าอยู่ในนั้นอาจเป็น tool ปกติ)
        if "program files" not in path_norm:
            risk_score += 30
            reasons.append("Single letter filename (suspicious dropper)")

    # ---------------------------------------------------------
    # Final Verdict
    # ---------------------------------------------------------
    
    # Threshold สามารถปรับได้ (50 คือเริ่มน่าสงสัย, 70+ คืออันตราย)
    suspicious = risk_score >= 50
    
    return suspicious, risk_score, reasons