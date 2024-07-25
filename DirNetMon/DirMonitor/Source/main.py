import os
import logging
import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import psutil
from scapy.all import sniff
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# File paths
LOG_FILE_DIRECTORY = "file_changes.log"
LOG_FILE_NETWORK = "network_activity.txt"

# Configure logging
logging.basicConfig(filename=LOG_FILE_NETWORK, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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

class DirectoryMonitorApp:
    def __init__(self, tab_control):
        self.tab = ttk.Frame(tab_control)
        tab_control.add(self.tab, text="Directory Monitor")
        self.setup_ui()

    def setup_ui(self):
        self.label = tk.Label(self.tab, text="Enter the directory to monitor:")
        self.label.pack(pady=10)

        self.directory_entry = tk.Entry(self.tab, width=50)
        self.directory_entry.pack(pady=5)

        self.start_button = tk.Button(self.tab, text="Start Monitoring", command=self._initiate_monitoring_process)
        self.start_button.pack(pady=20)

        self.status_label = tk.Label(self.tab, text="", fg="green")
        self.status_label.pack(pady=5)

        self.output_text = scrolledtext.ScrolledText(self.tab, width=48, height=10, state='disabled')
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
        self.output_text.after(100, self._append_to_output, message)

    def _append_to_output(self, message):
        self.output_text.insert(tk.END, message + '\n')
        self.output_text.see(tk.END)

def get_protocol_name(proto_num):
    protocols = {
        1: 'ICMP',
        6: 'TCP',
        17: 'UDP',
        41: 'IPv6',
        50: 'ESP',
        51: 'AH',
        58: 'ICMPv6'
    }
    return protocols.get(proto_num, 'Unknown')

def log_network_activity(packet):
    if packet.haslayer('IP'):
        src_ip = packet[0][1].src
        dst_ip = packet[0][1].dst
        proto_num = packet[0][1].proto
        proto_name = get_protocol_name(proto_num)
        log_message = f"Packet: {src_ip} -> {dst_ip} (Protocol: {proto_name})"
        logging.info(log_message)
        app.update_network_output(log_message)

def start_network_monitoring():
    # Start sniffing network packets in a separate thread
    threading.Thread(target=lambda: sniff(prn=log_network_activity, store=0), daemon=True).start()

class NetworkMonitorApp:
    def __init__(self, tab_control):
        self.tab = ttk.Frame(tab_control)
        tab_control.add(self.tab, text="Network Monitor")
        self.setup_ui()

    def setup_ui(self):
        self.start_button = tk.Button(self.tab, text="Start Network Monitoring", command=self._start_network_monitoring)
        self.start_button.pack(pady=20)

        self.output_text = scrolledtext.ScrolledText(self.tab, width=48, height=10, state='disabled')
        self.output_text.pack(pady=10)

    def _start_network_monitoring(self):
        self.output_text.config(state='normal')
        self.output_text.delete(1.0, tk.END)

        start_network_monitoring()

    def update_network_output(self, message):
        self.output_text.after(100, self._append_to_output, message)

    def _append_to_output(self, message):
        self.output_text.insert(tk.END, message + '\n')
        self.output_text.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    root.title("Malware Analysis Tool")
    root.geometry("600x500")

    tab_control = ttk.Notebook(root)
    tab_control.pack(expand=1, fill='both')

    app = NetworkMonitorApp(tab_control)
    directory_monitor_app = DirectoryMonitorApp(tab_control)

    root.mainloop()
