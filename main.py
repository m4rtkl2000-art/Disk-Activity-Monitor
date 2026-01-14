from imgui_bundle import hello_imgui, imgui
# เพิ่มการนำเข้าฟังก์ชันใหม่จาก disk_scanner
from disk_scanner import (
    scan_disk_usage, refresh_drives, kill_process_by_pid, 
    is_suspicious, get_file_hash, check_registry_persistence, 
    calculate_entropy
)
import threading
import logs as LOGs
import snapshot
import os
import subprocess
import webbrowser

# ------------------- Config -------------------
AVAILABLE_DRIVES = refresh_drives()

# ------------------- Global state -------------------
selected_drive_index = 0
drive_logs = {}
programs = []
has_scanned = False
is_scanning = False
scan_done = False
has_activity = False
search_query = ""
suspicious_logs = []
show_suspicious_window = False

# ------------------- Worker -------------------
def scan_worker(selected_drive):
    global drive_logs, programs, is_scanning, scan_done, has_scanned, has_activity
    global suspicious_logs, show_suspicious_window

    # 1. สแกนหา Activity พร้อม Genealogy
    drive_logs, programs, has_activity = scan_disk_usage(selected_drive)
    suspicious_logs = [] 
    
    # ดึงค่า Registry Persistence
    reg_items = check_registry_persistence()
    
    for drive_name, logs in drive_logs.items():
        for log in logs:
            is_susp, score, reasons = is_suspicious(log['path'], log['name'])
            is_new = snapshot.is_new_item(drive_name, log['pid'], log['path'])
            log['is_new'] = is_new

            # 2. Genealogy Check
            if log['name'].lower() == "lsass.exe" and log.get('parent_name', '').lower() != "wininit.exe":
                score += 50
                reasons.append(f"Suspicious Parent: {log['parent_name']}")

            # 3. Entropy & Hash (ทำเมื่อน่าสงสัยหรือเป็นไฟล์ใหม่)
            if is_susp or is_new:
                # คำนวณ Entropy
                ent = calculate_entropy(log['path'])
                log['entropy'] = ent
                if ent > 7.2:
                    score += 40
                    reasons.append(f"High Entropy ({ent:.2f}): Possible Ransomware")
                
                # คำนวณ Hash เพื่อใช้กับ VirusTotal
                f_hash = get_file_hash(log['path'])
                log['hash'] = f_hash
                if f_hash:
                    reasons.append(f"SHA256: {f_hash[:16]}...")

            # ตัดสินใจเพิ่มลงในรายการภัยคุกคาม
            if is_susp or score > 40:
                log_entry = log.copy() # ใช้ copy เพื่อให้ได้ค่า hash/entropy ล่าสุด
                log_entry['score'] = min(score, 100)
                log_entry['reasons'] = reasons
                
                if not any(s['pid'] == log['pid'] and s['path'] == log['path'] for s in suspicious_logs):
                    suspicious_logs.append(log_entry)

    # 4. Registry Check
    for item in reg_items:
        clean_path = item['path'].replace('"', '').split(' ')[0]
        if not os.path.exists(clean_path):
            suspicious_logs.append({
                "name": item['name'], "pid": "REG", "path": item['path'],
                "score": 60, "reasons": ["Persistence: Missing startup file"]
            })

    LOGs.save_scan_log(drive_logs, suspicious_logs)
    if suspicious_logs: show_suspicious_window = True
    has_scanned, is_scanning, scan_done = True, False, True

# ------------------- UI Components -------------------

def draw_control_panel():
    global selected_drive_index, is_scanning, has_scanned, scan_done
    global drive_logs, show_suspicious_window, suspicious_logs

    imgui.text_disabled("Control Panel")
    imgui.separator()

    # Drive Selector
    imgui.set_next_item_width(120)
    _, selected_drive_index = imgui.combo("Target Drive", selected_drive_index, AVAILABLE_DRIVES)
    imgui.same_line()

    # Scan Button
    if not is_scanning:
        if imgui.button("      SCAN      "):
            has_scanned, scan_done = False, False
            is_scanning = True
            selected_drive = None if selected_drive_index == 0 else AVAILABLE_DRIVES[selected_drive_index]
            threading.Thread(target=scan_worker, args=(selected_drive,), daemon=True).start()
    else:
        imgui.button("Scanning...")

    imgui.same_line()
    
    # Baseline Section
    if imgui.button("Set Baseline"):
        snapshot.set_baseline(drive_logs)

    imgui.same_line()
    current_drive_name = AVAILABLE_DRIVES[selected_drive_index]
    b_count = snapshot.get_baseline_count(None if selected_drive_index == 0 else current_drive_name)
    imgui.text_disabled(f"({current_drive_name} Base: {b_count})")

    imgui.same_line()
    if imgui.button("Open Logs"):
        log_dir = os.path.abspath("logs")
        if not os.path.exists(log_dir): os.makedirs(log_dir)
        os.startfile(log_dir)

    imgui.same_line()
    pushed_color = False
    if show_suspicious_window:
        imgui.push_style_color(imgui.Col_.button, (0.2, 0.6, 0.2, 1.0))
        pushed_color = True
    
    if imgui.button("View Threat Report"):
        show_suspicious_window = not show_suspicious_window
        
    if pushed_color:
        imgui.pop_style_color()

    if len(suspicious_logs) > 0:
        imgui.same_line()
        imgui.text_colored((1.0, 0.4, 0.4, 1.0), f"({len(suspicious_logs)} Threats)")

def draw_threat_report():
    global show_suspicious_window, suspicious_logs
    
    imgui.set_next_window_size((700, 550), imgui.Cond_.first_use_ever)
    is_open, show_suspicious_window = imgui.begin("⚠️ Advanced Threat Report", show_suspicious_window)
    
    if is_open:
        if not suspicious_logs:
            imgui.text_disabled("No threats detected.")
        else:
            imgui.begin_child("ReportContent")
            for item in suspicious_logs[:]:
                imgui.push_id(f"report_{item['pid']}_{item['path']}")
                
                # สีกำกับระดับความเสี่ยง
                s_color = (1.0, 0.2, 0.2, 1.0) if item['score'] >= 75 else (1.0, 0.6, 0.2, 1.0)
                imgui.text_colored(s_color, f"[Risk: {item['score']}/100]")
                imgui.same_line()
                imgui.text(f"{item['name']} (PID: {item['pid']})")
                
                imgui.indent()
                # แสดงข้อมูล Genealogy
                if 'parent_name' in item:
                    imgui.text_disabled(f"Parent: {item['parent_name']} (PID: {item.get('parent_pid', 'N/A')})")
                
                # แสดงเหตุผลและ Entropy
                for r in item['reasons']:
                    imgui.text_colored((0.8, 0.8, 0.8, 1.0), f"• {r}")
                
                if 'entropy' in item:
                    imgui.text_colored((0.4, 0.8, 0.4, 1.0), f"Entropy Score: {item['entropy']:.2f}")

                imgui.text_disabled(f"Location: {item['path']}")
                
                # --- Action Buttons ---
                if imgui.button(f"Reveal##{item['pid']}"):
                    subprocess.Popen(f'explorer /select,"{item["path"]}"')
                
                imgui.same_line()
                
                if item.get('hash'):
                    if imgui.button(f"VirusTotal##{item['pid']}"):
                        webbrowser.open(f"https://www.virustotal.com/gui/file/{item['hash']}")
                    imgui.same_line()

                imgui.push_style_color(imgui.Col_.button, (0.6, 0.2, 0.2, 1.0))
                if imgui.button(f"Terminate##{item['pid']}"):
                    if kill_process_by_pid(item['pid']):
                        suspicious_logs.remove(item)
                imgui.pop_style_color()

                imgui.unindent()
                imgui.separator()
                imgui.pop_id()
            imgui.end_child()
    imgui.end()

# ------------------- Main GUI Loop -------------------

def show_gui():
    global drive_logs, programs, has_scanned, is_scanning, scan_done, search_query, show_suspicious_window

    imgui.set_next_window_pos((0, 0))
    imgui.set_next_window_size(imgui.get_main_viewport().size)
    flags = (imgui.WindowFlags_.no_title_bar | imgui.WindowFlags_.no_resize | 
             imgui.WindowFlags_.no_move | imgui.WindowFlags_.no_collapse)

    imgui.begin("MainConsole", None, flags)
    draw_control_panel()

    if is_scanning:
        imgui.same_line(); imgui.text_colored((1, 1, 0, 1), f" Scanning{'.' * (int(imgui.get_time()*2)%4)}")
    elif scan_done:
        imgui.same_line(); imgui.text_colored((0.4, 1, 0.4, 1), " Scan Ready")

    imgui.spacing(); imgui.separator()
    imgui.text("Filter Search:"); imgui.set_next_item_width(300)
    _, search_query = imgui.input_text("##Search", search_query)
    
    avail = imgui.get_content_region_avail()
    left_w = avail.x * 0.7
    
    imgui.begin_child("LeftPanel", (left_w, 0), True)
    imgui.text("DRIVES USAGE LIST"); imgui.separator()
    
    if not has_scanned:
        imgui.text_disabled("System Idle. Press SCAN to begin monitoring.")
    else:
        for drive, logs in drive_logs.items():
            filtered = [l for l in logs if search_query.lower() in l['name'].lower() or search_query.lower() in l['path'].lower()]
            if filtered:
                if imgui.collapsing_header(f"Drive {drive} ({len(filtered)})", imgui.TreeNodeFlags_.default_open):
                    for log in filtered:
                        imgui.push_id(f"log_{log['pid']}_{log['path']}")
                        
                        if log.get('is_new'):
                            imgui.text_colored((0, 1, 0, 1), "[NEW]"); imgui.same_line()
                        
                        imgui.bullet_text(f"{log['name']} (PID: {log['pid']})")
                        
                        imgui.same_line(left_w - 150)
                        if imgui.button("Reveal"):
                            subprocess.Popen(f'explorer /select,"{log["path"]}"')
                        imgui.same_line()
                        
                        imgui.push_style_color(imgui.Col_.button, (0.5, 0.1, 0.1, 1))
                        if imgui.button("Kill"):
                            if kill_process_by_pid(log['pid']): logs.remove(log)
                        imgui.pop_style_color()

                        imgui.indent()
                        imgui.text_disabled(f"Parent: {log.get('parent_name', 'System')} | Path: {log['path']}")
                        if log.get('entropy'):
                            imgui.text_colored((0.5, 0.7, 0.5, 1), f"Entropy: {log['entropy']:.2f}")
                        imgui.unindent()
                        imgui.pop_id()
    imgui.end_child()

    imgui.same_line()

    imgui.begin_child("RightPanel", (0, 0), True)
    imgui.text("EXECUTABLES"); imgui.separator()
    if has_scanned:
        for p_name in programs:
            if search_query.lower() in p_name.lower(): imgui.bullet_text(p_name)
    imgui.end_child()

    if show_suspicious_window:
        draw_threat_report()

    imgui.end()

def main():
    # Auto-Baseline on Startup (Optional)
    # threading.Thread(target=scan_worker, args=(None,), daemon=True).start()

    params = hello_imgui.RunnerParams()
    params.app_window_params.window_title = "Disk Activity Monitor Pro v2.0"
    params.app_window_params.window_geometry.size = (1200, 900)
    params.callbacks.show_gui = show_gui
    hello_imgui.run(params)

if __name__ == "__main__":
    main()