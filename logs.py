import os
from datetime import datetime

def save_scan_log(all_logs, suspicious_list):
    """
    บันทึกผลการสแกนลงไฟล์ใหม่ทุกครั้ง: logs/disk_scanner_YYYYMMDD-HHMMSS.log
    """
    if not os.path.exists("logs"):
        os.makedirs("logs")

    # 1. สร้างชื่อไฟล์ตาม วันที่-เวลา ปัจจุบัน
    current_time = datetime.now()
    file_name = current_time.strftime("disk_scanner_%Y%m%d-%H%M%S.log")
    log_path = os.path.join("logs", file_name)
    
    timestamp_display = current_time.strftime("%Y-%m-%d %H:%M:%S")

    try:
        with open(log_path, "w", encoding="utf-8") as f:
            f.write(f"=== DISK ACTIVITY MONITOR SCAN REPORT ===\n")
            f.write(f"Scan Date: {timestamp_display}\n")
            f.write(f"Total Suspicious Items Found: {len(suspicious_list)}\n")
            f.write(f"==========================================\n\n")

            # --- ส่วนที่ 1: ไฟล์น่าสงสัย (Threats) ---
            if suspicious_list:
                f.write("[⚠️ SUSPICIOUS ACTIVITIES]\n")
                for item in suspicious_list:
                    f.write(f"- NAME: {item['name']} (PID: {item['pid']})\n")
                    f.write(f"  RISK SCORE: {item.get('score', 0)}\n")
                    f.write(f"  REASONS: {', '.join(item.get('reasons', []))}\n")
                    f.write(f"  PATH: {item['path']}\n\n")
            else:
                f.write("[✅ NO THREATS DETECTED]\n\n")

            f.write("------------------------------------------\n")

            # --- ส่วนที่ 2: ไฟล์ที่ทำงานอยู่ทั้งหมด (Normal Activity) ---
            f.write("[📄 ALL ACTIVE FILES ON DISK]\n")
            # drive_logs เป็น dictionary { 'C:\\': [log, log], ... }
            for drive, logs in all_logs.items():
                f.write(f"\nDrive {drive}:\n")
                if not logs:
                    f.write("  (No activity)\n")
                for log in logs:
                    f.write(f"  - [{log['pid']}] {log['name']} -> {log['path']}\n")

        print(f"Log report created: {log_path}")
        
    except Exception as e:
        print(f"Failed to write log file: {e}")