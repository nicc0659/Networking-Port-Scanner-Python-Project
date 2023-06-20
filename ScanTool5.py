#librerie necessarie 
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
        self.geometry("1000x1000")

        self.interface_var = tk.StringVar()
        self.target_var = tk.StringVar()
        self.network_scan_output = tk.StringVar()
        self.port_scan_output = tk.StringVar()

        self.create_widgets()

    #parte di interfaccia grafica con Tkinter
    def create_widgets(self):
        # Interface de label at du ComboBox
        interface_label = tk.Label(self, text="Interface:")
        interface_label.grid(row=0, column=0, sticky="w", padx=10, pady=10)
        interface_combobox = ttk.Combobox(self, textvariable=self.interface_var)
        interface_combobox.grid(row=0, column=1, sticky="w", padx=10, pady=10)

        # Interfaces Disponibles 
        interfaces = [adapter.name for adapter in ifaddr.get_adapters()]
        interface_combobox["values"] = interfaces

        # Target IP
        target_label = tk.Label(self, text="Target:")
        target_label.grid(row=1, column=0, sticky="w", padx=10, pady=10)

        targetexp_label = tk.Label(self, text="(Insert CIDR address for ARP, IP for SYN/UDP)")        
        targetexp_label.grid(row=2, column=0, sticky="w", padx=10, pady=10)

        target_entry = tk.Entry(self, textvariable=self.target_var)
        target_entry.grid(row=1, column=1, sticky="w", padx=10, pady=10)

        # Scan buttons implementati
        arp_button = tk.Button(self, text="ARP Scan", command=lambda: self.scan_network("arp"))
        arp_button.grid(row=3, column=0, pady=10)
        syn_button = tk.Button(self, text="SYN Scan", command=lambda: self.scan_ports("syn"))
        syn_button.grid(row=3, column=1, pady=10)

        # Status label (inizializzo)
        self.status_label = tk.Label(self, text="")
        self.status_label.grid(row=3, column=0, columnspan=2, pady=10)

        # Progress bar (anche determinate --> da guardare)
        self.progress_bar = ttk.Progressbar(self, mode="indeterminate", length=300)
        self.progress_bar.grid(row=4, column=0, columnspan=2, pady=10)

        # Network scan output text box (dove vengono mostrati gli output dell'arp scan)
        network_output_label = tk.Label(self, text="Network Scan Output:")
        network_output_label.grid(row=5, column=0, sticky="w", padx=10, pady=10)
        self.network_output_text = tk.Text(self, wrap="word", height=15, width=80)
        self.network_output_text.grid(row=6, column=0, columnspan=2, padx=10, pady=10)

        # Port scan output text box (per il syn and udp scan)
        port_output_label = tk.Label(self, text="Port Scan Output:")
        port_output_label.grid(row=7, column=0, sticky="w", padx=10, pady=10)
        self.port_output_text = tk.Text(self, wrap="word", height=15, width=80)
        self.port_output_text.grid(row=8, column=0, columnspan=2, padx=10, pady=10)

        # Start port label and entry (porta di inizio scan per il port scan)
        start_port_label = tk.Label(self, text="Start Port:")
        start_port_label.grid(row=1, column=2, sticky="w", padx=10, pady=10)
        self.start_port_var = tk.StringVar()
        start_port_entry = tk.Entry(self, textvariable=self.start_port_var)
        start_port_entry.grid(row=1, column=3, sticky="w", padx=10, pady=10)

        # End port label and entry (porta di fine scan per il port scan)
        end_port_label = tk.Label(self, text="End Port:")
        end_port_label.grid(row=2, column=2, sticky="w", padx=10, pady=10)
        self.end_port_var = tk.StringVar()
        end_port_entry = tk.Entry(self, textvariable=self.end_port_var)
        end_port_entry.grid(row=2, column=3, sticky="w", padx=10, pady=10)

        udp_button = tk.Button(self, text="UDP Scan", command=lambda: self.scan_ports("udp"))
        udp_button.grid(row=3, column=2, pady=10)

        self.stop_scan_button = tk.Button(self, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_scan_button.grid(row=3, column=3, pady=10)

    #funzione che arresta lo scan, sia per thread che sulla GUI
    def stop_scan(self):
        if self.scan_thread.is_alive():
            # Terminate the scan thread
            self.scan_thread.join(0)
            self.status_label.config(text="Scan stopped.")
            self.progress_bar.stop()
            self.stop_scan_button.config(state=tk.DISABLED)

    #funzione che inizializza lo scan della rete e attiva la progressbar 
    def scan_network(self, scan_type): 
        self.progress_bar.start()
        self.network_output_text.delete(1.0, tk.END)
        threading.Thread(target=self.run_network_scan, args=(scan_type,)).start()

    #esegue lo scan della funzione, gli scan possono essere arp o ping per la rete (ICMP / TCP)
    def run_network_scan(self, scan_type):
        self.status_label.config(text="Scanning network...")
        target = self.target_var.get()
        if not target:
            self.network_output_text.insert(tk.END, "Please enter a target IP address or range.\n")
            self.status_label.config(text="")
            self.progress_bar.stop()
            return

        if scan_type == "arp":
                nm = nmap.PortScanner()
                nm.scan(hosts=target, arguments="-sn")
                for host in nm.all_hosts():
                    self.network_output_text.insert(tk.END, f"{host}\n")
        elif scan_type == "ping":
                nm = nmap.PortScanner()
                nm.scan(hosts=target, arguments="-PE")
                for host in nm.all_hosts():
                    self.network_output_text.insert(tk.END, f"{host}\n")
        else:
                nm = nmap.PortScanner()
                nm.scan(hosts=target, arguments="-sP")
                for host in nm.all_hosts():
                    self.network_output_text.insert(tk.END, f"{host}\n")
        self.status_label.config(text="Scan complete.")
        self.progress_bar.stop()

    #funzione che inizializza lo scan dell'inidirzzo IP e attiva la progressbar
    def scan_ports(self, scan_type):
        self.progress_bar.start()
        self.port_output_text.delete(1.0, tk.END)
        threading.Thread(target=self.run_port_scan, args=(scan_type,)).start()

    #esegue lo scan specificato e fa controllo di non-inserimento target 
    def run_port_scan(self, scan_type):
        self.port_output_text.delete(1.0, tk.END)
        self.status_label.config(text="Scanning ports...")
        self.progress_bar.start()
        self.stop_scan_button.config(state=tk.NORMAL)
        target = self.target_var.get()
        start_port = int(self.start_port_var.get())
        end_port = int(self.end_port_var.get())
        if not target:
            self.port_output_text.insert(tk.END, "Please enter a target IP address.\n")
            self.status_label.config(text="")
            self.progress_bar.stop()
            return
        self.scan_thread = threading.Thread(target=self.perform_scan, args=(target, start_port, end_port, scan_type))
        self.scan_thread.start()

    #esegue lo scan dell'indirizzo IP, gli scan possono essere syn oppure di default udp.
    def perform_scan(self, target, start_port, end_port, scan_type):
        nm = nmap.PortScanner()
        port_range = f"{start_port}-{end_port}"
        arguments = f"-p {port_range} -sS" if scan_type == "syn" else f"-p {port_range} -sU"
        nm.scan(hosts=target, arguments=arguments)
        for host in nm.all_hosts():
            self.port_output_text.insert(tk.END, f"Host: {host}\n")
            tcp_ports = []
            udp_ports = []
            for proto in nm[host].all_protocols():
                self.port_output_text.insert(tk.END, f"Protocol: {proto}\n")
                lport = nm[host][proto].keys()
                for port in sorted(lport):
                    if proto == "tcp":
                        tcp_ports.append(port)
                    elif proto == "udp":
                        udp_ports.append(port)
            if tcp_ports:
                self.port_output_text.insert(tk.END, f"TCP Ports: {', '.join(map(str, tcp_ports))}\n")
            if udp_ports:
                self.port_output_text.insert(tk.END, f"UDP Ports: {', '.join(map(str, udp_ports))}\n")
            self.port_output_text.insert(tk.END, "\n")
        self.status_label.config(text="Scan complete.")
        self.progress_bar.stop()
        self.stop_scan_button.config(state=tk.DISABLED)

if __name__ == "__main__":
    app = NetworkScannerApp()
    app.mainloop()