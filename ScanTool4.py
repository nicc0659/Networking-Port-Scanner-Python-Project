import tkinter as tk
from tkinter import ttk
import nmap
import threading
import ifaddr
import socket

class NetworkScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Scanner")
        self.geometry("800x600")

        self.interface_var = tk.StringVar()
        self.target_var = tk.StringVar()
        self.network_scan_output = tk.StringVar()
        self.port_scan_output = tk.StringVar()

        self.create_widgets()

    def create_widgets(self):
        # Interface label and ComboBox
        interface_label = tk.Label(self, text="Interface:")
        interface_label.grid(row=0, column=0, sticky="w", padx=10, pady=10)
        interface_combobox = ttk.Combobox(self, textvariable=self.interface_var)
        interface_combobox.grid(row=0, column=1, sticky="w", padx=10, pady=10)

        # Populate ComboBox with available interfaces
        interfaces = [adapter.name for adapter in ifaddr.get_adapters()]
        interface_combobox["values"] = interfaces

        # Target label and entry
        target_label = tk.Label(self, text="Target:")
        target_label.grid(row=1, column=0, sticky="w", padx=10, pady=10)
        target_entry = tk.Entry(self, textvariable=self.target_var)
        target_entry.grid(row=1, column=1, sticky="w", padx=10, pady=10)

        # Scan buttons
        arp_button = tk.Button(self, text="ARP Scan", command=lambda: self.scan_network("arp"))
        arp_button.grid(row=2, column=0, pady=10)
        syn_button = tk.Button(self, text="SYN Scan", command=lambda: self.scan_ports("syn"))
        syn_button.grid(row=2, column=1, pady=10)

        # Progress bar
        self.progress_bar = ttk.Progressbar(self, mode="indeterminate", length=300)
        self.progress_bar.grid(row=3, column=0, columnspan=2, pady=10)

        # Network scan output text box
        network_output_label = tk.Label(self, text="Network Scan Output:")
        network_output_label.grid(row=4, column=0, sticky="w", padx=10, pady=10)
        self.network_output_text = tk.Text(self, wrap="word", height=15, width=80)
        self.network_output_text.grid(row=5, column=0, columnspan=2, padx=10, pady=10)

        # Port scan output text box
        port_output_label = tk.Label(self, text="Port Scan Output:")
        port_output_label.grid(row=6, column=0, sticky="w", padx=10, pady=10)
        self.port_output_text = tk.Text(self, wrap="word", height=15, width=80)
        self.port_output_text.grid(row=7, column=0, columnspan=2, padx=10, pady=10)

    def scan_network(self, scan_type):
        self.progress_bar.start()
        self.network_output_text.delete(1.0, tk.END)
        threading.Thread(target=self.run_network_scan, args=(scan_type,)).start()

    def run_network_scan(self, scan_type):
        target = self.target_var.get()
        if not target:
            self.network_output_text.insert(tk.END, "Please enter a target IP address or range.\n")
            return

        nm = nmap.PortScanner()
        try:
            if scan_type == "arp":
                scan_data = nm.scan(hosts=target, arguments='-sn -PR')
            elif scan_type == "icmp":
                scan_data = nm.scan(hosts=target, arguments='-sn -PE')
            elif scan_type == "sntp":
                scan_data = nm.scan(hosts=target, arguments='-sn -PS123')
            else:
                self.network_output_text.insert(tk.END, f"Unknown scan type: {scan_type}\n")
                return

            for host in scan_data["scan"]:
                try:
                    hostname = socket.gethostbyaddr(host)[0]
                except socket.herror:
                    hostname = "Unknown"
                self.network_output_text.insert(tk.END, f"{host} ({hostname})\n")

        except nmap.PortScannerError as e:
            self.network_output_text.insert(tk.END, f"Error: {e}\n")

        finally:
            self.progress_bar.stop()

    def scan_ports(self, scan_type):
        self.progress_bar.start()
        self.port_output_text.delete(1.0, tk.END)
        threading.Thread(target=self.run_port_scan, args=(scan_type,)).start()

    def run_port_scan(self, scan_type):
        target = self.target_var.get()
        if not target:
            self.port_output_text.insert(tk.END, "Please enter a target IP address.\n")
            return

        nm = nmap.PortScanner()
        try:
            if scan_type == "syn":
                scan_data = nm.scan(hosts=target, arguments='-sS')
            else:
                self.port_output_text.insert(tk.END, f"Unknown scan type: {scan_type}\n")
                return

            for host in scan_data["scan"]:
                open_ports = [port for port in scan_data["scan"][host]["tcp"] if scan_data["scan"][host]["tcp"][port]["state"] == "open"]
                if open_ports:
                    self.port_output_text.insert(tk.END, f"{host} open ports: {', '.join(map(str, open_ports))}\n")
                else:
                    self.port_output_text.insert(tk.END, f"{host} has no open ports.\n")

        except nmap.PortScannerError as e:
            self.port_output_text.insert(tk.END, f"Error: {e}\n")

        finally:
            self.progress_bar.stop()

if __name__ == "__main__":
    app = NetworkScannerApp()
    app.mainloop()
