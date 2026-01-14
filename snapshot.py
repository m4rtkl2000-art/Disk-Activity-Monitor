# snapshot.py

# เปลี่ยนจาก set ธรรมดา เป็น dictionary { 'C:\\': set(), 'E:\\': set() }
_baseline_data_map = {}

def set_baseline(drive_logs):
    """
    บันทึกสถานะปัจจุบันแยกตามไดรฟ์
    drive_logs: dict { 'C:\\': [log, log], 'E:\\': [...] }
    """
    global _baseline_data_map
    
    total_items = 0
    # วนลูปตามไดรฟ์ที่มีข้อมูลเข้ามา
    for drive, logs in drive_logs.items():
        drive_set = set()
        for log in logs:
            # เก็บ (PID, Path) เพื่อระบุตัวตน
            drive_set.add((log['pid'], log['path']))
        
        _baseline_data_map[drive] = drive_set
        total_items += len(drive_set)
        
    return total_items

def is_new_item(drive, pid, path):
    """
    ตรวจสอบแยกตามไดรฟ์
    """
    # ถ้าไดรฟ์นี้ยังไม่มี Baseline ให้ถือว่าไม่ใช่ของใหม่ (เพื่อความปลอดภัยไม่ให้เตือนมั่ว)
    if drive not in _baseline_data_map:
        return False
        
    return (pid, path) not in _baseline_data_map[drive]

def get_baseline_count(drive=None):
    """
    คืนค่าจำนวนรายการใน Baseline (ระบุไดรฟ์ หรือ ทั้งหมด)
    """
    if drive:
        return len(_baseline_data_map.get(drive, set()))
    return sum(len(s) for s in _baseline_data_map.values())