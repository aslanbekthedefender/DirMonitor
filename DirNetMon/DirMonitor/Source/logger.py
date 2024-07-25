import os

def log_event(event):
    log_file_path = os.path.join(os.path.dirname(__file__), "file_changes.log")
    with open(log_file_path, "a", encoding="utf-8") as log_file:
        log_file.write(f"{event}\n")
