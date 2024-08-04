import os
import logging
import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import config
import network_monitoring  # Import the network monitoring module

# Configure logging for directory changes
logging.basicConfig(filename=config.LOG_FILE_DIRECTORY, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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

        self.stop_button = tk.Button(self.tab, text="Stop Monitoring", command=self._stop_monitoring_process, state=tk.DISABLED)
        self.stop_button.pack(pady=5)

        self.status_label = tk.Label(self.tab, text="", fg="green")
        self.status_label.pack(pady=5)

        self.output_text = scrolledtext.ScrolledText(self.tab, width=48, height=10, state='disabled')
        self.output_text.pack(pady=10)

        self.observer = None

    def _initiate_monitoring_process(self):
        monitor_path = self.directory_entry.get()
        if not os.path.exists(monitor_path):
            messagebox.showerror("Error", f"Directory {monitor_path} does not exist.")
            return

        with open(config.LOG_FILE_DIRECTORY, 'a', encoding='utf-8'):
            pass

        self.status_label.config(text="Monitoring...")
        self.output_text.config(state='normal')
        self.output_text.delete(1.0, tk.END)

        event_handler = DirectoryEventHandler(config.LOG_FILE_DIRECTORY, self._update_output_display)
        self.observer = Observer()
        self.observer.schedule(event_handler, path=monitor_path, recursive=True)
        self.observer.start()

        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        threading.Thread(target=self._maintain_observer_lifecycle, args=(self.observer,), daemon=True).start()

    def _stop_monitoring_process(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.status_label.config(text="Monitoring stopped.")
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)

    def _maintain_observer_lifecycle(self, observer):
        try:
            while observer.is_alive():
                pass
        except KeyboardInterrupt:
            observer.stop()
        observer.join()

    def _update_output_display(self, message):
        self.output_text.after(100, self._append_to_output, message)

    def _append_to_output(self, message):
        self.output_text.insert(tk.END, message + '\n')
        self.output_text.see(tk.END)

class NetworkMonitorApp:
    def __init__(self, tab_control):
        self.tab = ttk.Frame(tab_control)
        tab_control.add(self.tab, text="Network Monitor")
        self.setup_ui()

    def setup_ui(self):
        self.interface_label = tk.Label(self.tab, text="Select Network Interface:")
        self.interface_label.pack(pady=10)

        self.interface_var = tk.StringVar()
        self.interface_dropdown = ttk.Combobox(self.tab, textvariable=self.interface_var)
        self.interface_dropdown.pack(pady=5)
        self._populate_interface_dropdown()

        self.start_button = tk.Button(self.tab, text="Start Network Monitoring", command=self._start_network_monitoring)
        self.start_button.pack(pady=20)

        self.stop_button = tk.Button(self.tab, text="Stop Network Monitoring", command=self._stop_network_monitoring, state=tk.DISABLED)
        self.stop_button.pack(pady=5)

        self.output_text = scrolledtext.ScrolledText(self.tab, width=48, height=10, state='disabled')
        self.output_text.pack(pady=10)

        self.network_thread = None

    def _populate_interface_dropdown(self):
        interfaces = psutil.net_if_addrs()
        interface_names = [iface for iface in interfaces]
        self.interface_dropdown['values'] = interface_names
        if interface_names:
            self.interface_var.set(interface_names[0])

    def _start_network_monitoring(self):
        selected_interface = self.interface_var.get()
        if not selected_interface or selected_interface not in psutil.net_if_addrs():
            messagebox.showerror("Error", "Invalid network interface selected.")
            return

        self.output_text.config(state='normal')
        self.output_text.delete(1.0, tk.END)

        self.network_thread = threading.Thread(target=lambda: network_monitoring.start_network_monitoring(selected_interface, self), daemon=True)
        self.network_thread.start()

        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

    def _stop_network_monitoring(self):
        if self.network_thread and self.network_thread.is_alive():
            # Terminate the network monitoring thread
            # Note: You might need to use a more graceful way to stop sniffing in a real scenario
            self.network_thread.join(timeout=1)

        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

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

    directory_monitor_app = DirectoryMonitorApp(tab_control)
    network_monitor_app = NetworkMonitorApp(tab_control)

    root.mainloop()
