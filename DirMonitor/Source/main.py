import os
import logging
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

LOG_FILE_DIRECTORY = "file_changes.log"

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class DirectoryEventHandler(FileSystemEventHandler):
    def __init__(self, log_file, output_handler):
        super().__init__()
        self.log_file = log_file
        self.output_handler = output_handler

    def on_modified(self, event):
        if event.src_path != os.path.abspath(self.log_file):
            log_message = f"Modified: {event.src_path}"
            logging.info(log_message)
            self._append_log_entry(log_message)
            self.output_handler(log_message)

    def on_created(self, event):
        if event.src_path != os.path.abspath(self.log_file):
            log_message = f"Created: {event.src_path}"
            logging.info(log_message)
            self._append_log_entry(log_message)
            self.output_handler(log_message)

    def on_deleted(self, event):
        if event.src_path != os.path.abspath(self.log_file):
            log_message = f"Deleted: {event.src_path}"
            logging.info(log_message)
            self._append_log_entry(log_message)
            self.output_handler(log_message)

    def _append_log_entry(self, message):
        with open(self.log_file, 'a', encoding='utf-8') as file:
            file.write(message + '\n')

class DirectoryMonitoringApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Directory Monitor")
        self.master.geometry("400x300")

        self.label = tk.Label(master, text="Enter the directory to monitor:")
        self.label.pack(pady=10)

        self.directory_entry = tk.Entry(master, width=50)
        self.directory_entry.pack(pady=5)

        self.start_button = tk.Button(master, text="Start Monitoring", command=self._initiate_monitoring_process)
        self.start_button.pack(pady=20)

        self.status_label = tk.Label(master, text="", fg="green")
        self.status_label.pack(pady=5)

        self.output_text = scrolledtext.ScrolledText(master, width=48, height=10, state='disabled')
        self.output_text.pack(pady=10)

    def _initiate_monitoring_process(self):
        monitor_path = self.directory_entry.get()
        if not os.path.exists(monitor_path):
            messagebox.showerror("Error", f"Directory {monitor_path} does not exist.")
            return
        
        with open(LOG_FILE_DIRECTORY, 'a', encoding='utf-8'):
            pass
        
        self.status_label.config(text="Monitoring...")
        self.output_text.config(state='normal')
        self.output_text.delete(1.0, tk.END)

        event_handler = DirectoryEventHandler(LOG_FILE_DIRECTORY, self._update_output_display)
        observer = Observer()
        observer.schedule(event_handler, path=monitor_path, recursive=True)
        observer.start()

        threading.Thread(target=self._maintain_observer_lifecycle, args=(observer,), daemon=True).start()

    def _maintain_observer_lifecycle(self, observer):
        try:
            while True:
                pass
        except KeyboardInterrupt:
            observer.stop()
        observer.join()

    def _update_output_display(self, message):
        self.output_text.insert(tk.END, message + '\n')
        self.output_text.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = DirectoryMonitoringApp(root)
    root.mainloop()
