import tkinter as tk
from tkinter import ttk
import nmap
import threading
import ifaddr
import socket
import scapy.all as scapy

class NetworkScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Scanner")
        self.geometry("1000x1000")

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
        ping_button = tk.Button(self, text="Ping Scan", command=lambda: self.scan_network("ping"))
        ping_button.grid(row=2, column=1, pady=10)
        syn_button = tk.Button(self, text="SYN Scan", command=lambda: self.scan_ports("syn"))
        syn_button.grid(row=2, column=2, pady=10)
        udp_button = tk.Button(self, text="UDP Scan", command=lambda: self.scan_ports("udp"))
        udp_button.grid(row=2, column=3, pady=10)

        # Status label
        self.status_label = tk.Label(self, text="")
        self.status_label.grid(row=3, column=0, columnspan=4, pady=10)

        # Progress bar
        self.progress_bar = ttk.Progressbar(self, mode="indeterminate", length=300)
        self.progress_bar.grid(row=4, column=0, columnspan=4, pady=10)

        # Network scan output text box
        network_output_label = tk.Label(self, text="Network Scan Output:")
        network_output_label.grid(row=5, column=0, sticky="w", padx=10, pady=10)
        self.network_output_text = tk.Text(self, wrap="word", height=15, width=80)
        self.network_output_text.grid(row=6, column=0, columnspan=4, padx=10, pady=10)

        # Port scan output text box
        port_output_label = tk.Label(self, text="Port Scan Output:")
        port_output_label.grid(row=7, column=0, sticky="w", padx=10, pady=10)
        self.port_output_text = tk.Text(self, wrap="word", height=15, width=80)
        self.port_output_text.grid(row=8, column=0, columnspan=4, padx=10, pady=10)

        # Start port label and entry
        start_port_label = tk.Label(self, text="Start Port:")
        start_port_label.grid(row=1, column=2, sticky="w", padx=10, pady=10)
        self.start_port_var = tk.StringVar()
        start_port_entry = tk.Entry(self, textvariable=self.start_port_var)
        start_port_entry.grid(row=1, column=3, sticky="w", padx=10, pady=10)

        # End port label and entry
        end_port_label = tk.Label(self, text="End Port:")
        end_port_label.grid(row=2, column=4, sticky="w", padx=10, pady=10)
        self.end_port_var = tk.StringVar()
        end_port_entry = tk.Entry(self, textvariable=self.end_port_var)
        end_port_entry.grid(row=2, column=5, sticky="w", padx=10, pady=10)

        self.stop_scan_button = tk.Button(self, text="Stop Scan", command=self.stop_scan,state="disabled")
        self.stop_scan_button.grid(row=2, column=6, pady=10)

    def update_status(self, status):
        self.status_label.config(text=status)

    def scan_network(self, mode):
        target = self.target_var.get().strip()

        if not target:
            self.update_status("Error: Please enter a target IP address or network range.")
            return

        self.start_scan()

        def run_scan():
            nm = nmap.PortScanner()
            try:  
                if mode == "arp": 
                    arp_result = {}          
                    arp_request = scapy.ARP(pdst=target)
                    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                    arp_request_broadcast = broadcast/arp_request
                    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]    
                    for element in answered_list: 
                        ip = element[1].psrc    
                        mac = element[1].hwsrc    
                        arp_result[ip] = mac                        
                elif mode == "ping":
                    scan_result = nm.scan(hosts=target, arguments="-sn")
            except nmap.PortScannerError as e:
                self.stop_scan()
                self.update_status(f"Error: {str(e)}")
                return

            self.network_output_text.delete(1.0, tk.END)
            for host in scan_result["scan"]:
                ip = scan_result["scan"][host]["addresses"]["ipv4"]
                status = scan_result["scan"][host]["status"]["state"]
                self.network_output_text.insert(tk.END, f"{ip}: {status}\n")

            self.stop_scan()

        threading.Thread(target=run_scan).start()

    def scan_ports(self, mode):
        target = self.target_var.get().strip()
        start_port = self.start_port_var.get().strip()
        end_port = self.end_port_var.get().strip()

        if not target:
            self.update_status("Error: Please enter a target IP address.")
            return

        if not start_port or not end_port:
            self.update_status("Error: Please enter a valid start and end port range.")
            return

        try:
            start_port = int(start_port)
            end_port = int(end_port)
        except ValueError:
            self.update_status("Error: Start and end ports must be integers.")
            return

        if start_port < 1 or start_port > 65535 or end_port < 1 or end_port > 65535:
            self.update_status("Error: Port range must be between 1 and 65535.")
            return

        self.start_scan()

        def run_scan():
            nm = nmap.PortScanner()
            try:
                if mode == "arp":
                    # ... (previous code remains the same) ...
                    scan_result = {"scan": arp_result}  # Assign the arp_result to the "scan" key
                elif mode == "ping":
                    scan_result = nm.scan(hosts=target, arguments="-sn")
            except nmap.PortScannerError as e:
                self.stop_scan()
                self.update_status(f"Error: {str(e)}")
                return

            self.port_output_text.delete(1.0, tk.END)
            for host in scan_result["scan"]:
                ip = scan_result["scan"][host]["addresses"]["ipv4"]
                for proto in scan_result["scan"][host]["tcp"]:
                    port = proto
                    state = scan_result["scan"][host]["tcp"][proto]["state"]
                    self.port_output_text.insert(tk.END, f"{ip}:{port}/{mode} - {state}\n")  

            self.stop_scan()

        threading.Thread(target=run_scan).start()

    def start_scan(self):
        self.progress_bar.start()
        self.stop_scan_button.config(state="normal")

    def stop_scan(self):
        self.progress_bar.stop()
        self.update_status("")
        self.stop_scan_button.config(state="disabled")

    def stop_scan(self):
        self.progress_bar.stop()
        self.update_status("Scan stopped.")
        self.stop_scan_button.config(state="disabled")


if __name__ == "__main__":
    app = NetworkScannerApp()
    app.mainloop()