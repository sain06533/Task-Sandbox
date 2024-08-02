import tkinter as tk
from tkinter import ttk
import psutil
import os
import subprocess
import requests
import sys
import hashlib
import argparse
import logging
import json
import time

selected_process_path = None  # Global variable to store the selected process path
VIRUSTOTAL_API_KEY = "674151705eb70883bdae88e444776e5442afdf6200baab8cf608339aee6e6881" #enter your virus total API key

def get_running_processes():
    """Get a list of running processes."""
    return psutil.process_iter(attrs=["pid", "name", "cpu_percent", "memory_info"])

def open_file_location(process_pid):
    """Open the file location of a process."""
    global selected_process_path  # Use the global variable
    try:
        process = psutil.Process(process_pid)
        file_path = process.exe()
        selected_process_path = os.path.dirname(file_path)  # Store the directory of the selected process
        subprocess.Popen(f'explorer /select,"{file_path}"')  # Open the directory and select the file
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        print(f"Error: Unable to open file location for process with PID {process_pid}")

def show_processes():
    """Display the list of running processes in the GUI."""
    process_table.delete(*process_table.get_children())  # Clear existing entries
    processes = []
    for proc in get_running_processes():
        process_name = proc.info["name"]
        process_pid = proc.info["pid"]
        cpu_percent = proc.info["cpu_percent"]
        memory_info = proc.info["memory_info"]
        ram_usage_mb = memory_info.rss / (1024 ** 2)  # Convert bytes to megabytes
        processes.append((process_name, process_pid, f"{cpu_percent:.2f}%", f"{ram_usage_mb:.2f} MB"))
    
    # Sort processes based on RAM usage (column index 3)
    processes.sort(key=lambda x: float(x[3].split()[0]), reverse=True)
    
    # Insert sorted processes into the table
    for process in processes:
        process_table.insert("", tk.END, values=process)

def on_process_selected(event):
    """Handle process selection event."""
    selection = process_table.selection()
    if selection:
        process_pid_str = process_table.item(selection[0], "values")[1]  # Extract process PID as a string
        try:
            process_pid = int(process_pid_str)  # Convert the PID string to an integer
            open_file_location(process_pid)
        except ValueError:
            print(f"Error: Unable to convert '{process_pid_str}' to an integer for process PID")

def sort_column(tree, col, reverse):
    """Sort the treeview by given column."""
    data = [(float(tree.set(child, col).split()[0]), child) for child in tree.get_children('')]
    data.sort(reverse=reverse)

    for index, (val, child) in enumerate(data):
        tree.move(child, '', index)

    tree.heading(col, command=lambda: sort_column(tree, col, not reverse))

def list_all_files(path):
    assert os.path.isfile(path) or os.path.isdir(path)

    if os.path.isfile(path):
        return [path]
    else:
        return filter(os.path.isfile, map(lambda x: '/'.join([os.path.abspath(path), x]), os.listdir(path)))


def sha256sum(filename):
    with open(filename, 'rb') as f:
        m = hashlib.sha256()
        while True:
            data = f.read(8192)
            if not data:
                break
            m.update(data)
        return m.hexdigest()

class VirusTotal(object):
    def __init__(self):
        self.apikey = "674151705eb70883bdae88e444776e5442afdf6200baab8cf608339aee6e6881A"
        self.URL_BASE = "https://www.virustotal.com/vtapi/v2/"
        self.HTTP_OK = 200

        # whether the API_KEY is a public API. limited to 4 per min if so.
        self.is_public_api = True
        # whether a retrieval request is sent recently
        self.has_sent_retrieve_req = False
        # if needed (public API), sleep this amount of time between requests
        self.PUBLIC_API_SLEEP_TIME = 20

        self.logger = logging.getLogger("virt-log")
        self.logger.setLevel(logging.INFO)
        self.scrlog = logging.StreamHandler()
        self.scrlog.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        self.logger.addHandler(self.scrlog)
        self.is_verboselog = False  #can cahange this to true for more information

    def retrieve_files_reports(self, filenames):
        """
        Retrieve Report for file

        @param filename: target file
        """
        for filename in filenames:
            res = self.retrieve_report(sha256sum(filename))

            if res.status_code == self.HTTP_OK:
                resmap = json.loads(res.text)
                if not self.is_verboselog:
                    self.logger.info("retrieve report: %s, HTTP: %d, response_code: %d, scan_date: %s, positives/total: %d/%d",
                            os.path.basename(filename), res.status_code, resmap["response_code"], resmap["scan_date"], resmap["positives"], resmap["total"])
                else:
                    self.logger.info("retrieve report: %s, HTTP: %d, content: %s", os.path.basename(filename), res.status_code, res.text)
            else:
                self.logger.warning("retrieve report: %s, HTTP: %d", os.path.basename(filename), res.status_code)

    def retrieve_report(self, chksum):
        if self.has_sent_retrieve_req and self.is_public_api:
            time.sleep(self.PUBLIC_API_SLEEP_TIME)

        url = self.URL_BASE + "file/report"
        params = {"apikey": self.apikey, "resource": chksum}
        res = requests.post(url, data=params)
        self.has_sent_retrieve_req = True
        return res

def scan_with_virustotal(file_path):
    """Submit a file to VirusTotal for analysis."""
    vt = VirusTotal()
    vt.apikey = VIRUSTOTAL_API_KEY
    vt.retrieve_files_reports(list_all_files(file_path))

def scan_selected_process():
    """Scan the selected process with VirusTotal."""
    global selected_process_path  # Use the global variable
    if selected_process_path is not None:
        selection = process_table.selection()
        if selection:
            process_name = process_table.item(selection[0], "values")[0]  # Extract process name
            scan_with_virustotal(os.path.join(selected_process_path, f"{process_name}"))
    else:
        print("Error: Please select a process and open its file location before scanning with VirusTotal.")

# Create the main window
root = tk.Tk()
root.title("Enhanced Task Manager")
root.geometry("800x400")  # Set initial window size

# Create a Treeview widget to display processes in a table
process_table = ttk.Treeview(root, columns=("Name", "Process ID", "CPU %", "RAM Usage"), show="headings")
process_table.heading("Name", text="Name", command=lambda: sort_column(process_table, "Name", False))
process_table.heading("Process ID", text="Process ID", command=lambda: sort_column(process_table, "Process ID", False))
process_table.heading("CPU %", text="CPU %", command=lambda: sort_column(process_table, "CPU %", False))
process_table.heading("RAM Usage", text="RAM Usage (MB)", command=lambda: sort_column(process_table, "RAM Usage", True))
process_table.pack(fill=tk.BOTH, expand=True)  # Make table expand with window

# Button to refresh process list
refresh_button = tk.Button(root, text="Refresh", command=show_processes)
refresh_button.pack()

# Button to open file location
open_location_button = tk.Button(root, text="Open File Location", command=lambda: on_process_selected(None))
open_location_button.pack()

# Button to scan selected process with VirusTotal
scan_button = tk.Button(root, text="Scan", command=scan_selected_process)
scan_button.pack()

# Bind double-click event to open file location
process_table.bind("<Double-1>", on_process_selected)

# Initial process list
show_processes()

# Start the GUI event loop
root.mainloop()
