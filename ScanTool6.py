import tkinter as tk
from tkinter import ttk
import tkinter.font as tkFont
import nmap
from scapy.all import ARP, Ether, srp
import pyshark
import socket
import threading

# Main GUI window
window = tk.Tk()
window.title("Network Tool")

# Upscale factor
scale_factor = 2

# Adjust font size for all widgets
default_font = tkFont.nametofont("TkDefaultFont")
default_font.configure(size=int(default_font['size'] * scale_factor))

# Port scanner function
def port_scanner(progress, output_text):
    nm = nmap.PortScanner()
    target = target_entry.get()
    start_port = start_port_entry.get()
    end_port = end_port_entry.get()
    ports = f"{start_port}-{end_port}"
    nm.scan(hosts=target, ports=ports, arguments='-Pn')

    for host in nm.all_hosts():
        output_text.insert(tk.END, f"Host: {host} ({nm[host].hostname()})\n")
        output_text.update_idletasks()
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                output_text.insert(tk.END, f"Port: {port}, State: {nm[host][proto][port]['state']}\n")
                output_text.update_idletasks()

    progress.stop()

# Network scanner function
def network_scanner(progress, output_text):
    ip_range = ip_entry.get()
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered, _ = srp(arp_request_broadcast, timeout=1, verbose=False)

    for sent, received in answered:
        output_text.insert(tk.END, f"IP: {received.psrc}, MAC: {received.hwsrc}\n")
        output_text.update_idletasks()

    progress.stop()

# Packet analyzer function
def packet_analyzer(packet, progress, output_text):
    output_text.insert(tk.END, f"{packet}\n")
    output_text.update_idletasks()

    progress.stop()

def start_packet_analyzer(progress, output_text):
    interface = interface_var.get()
    filter_text = filter_entry.get()
    capture = pyshark.LiveCapture(interface=interface, display_filter=filter_text)
    capture.apply_on_packets(lambda packet: packet_analyzer(packet, progress, output_text), timeout=10)

# Get available network interfaces
def get_available_interfaces():
    return [iface[1] for iface in socket.if_nameindex()]

def create_label_entry(parent, label_text, row):
    label = ttk.Label(parent, text=label_text)
    label.grid(column=0, row=row, padx=5 * scale_factor, pady=5 * scale_factor)
    entry = ttk.Entry(parent, font=default_font)
    entry.grid(column=1, row=row, padx=5 * scale_factor, pady=5 * scale_factor)
    return entry

# Create a progress bar
def progress_bar(tab):
    progress = ttk.Progressbar(tab, mode="indeterminate", length=200 * scale_factor)
    progress.grid(column=1, row=4, padx=5 * scale_factor, pady=5 * scale_factor)
    progress.start()
    return progress

# Create tabs
tab_control = ttk.Notebook(window)
tab1 = ttk.Frame(tab_control)
tab2 = ttk.Frame(tab_control)
tab3 = ttk.Frame(tab_control)
tab_control.add(tab1, text="Port Scanner")
tab_control.add(tab2, text="Network Scanner")
tab_control.add(tab3, text="Packet Analyzer")
tab_control.pack(expand=1, fill="both")

# Create output text boxes for each tab
output_text1 = tk.Text(tab1, wrap="word", width=60 * scale_factor, height=20 * scale_factor, font=default_font)
output_text1.pack(padx=5 * scale_factor, pady=5 * scale_factor)

output_text2 = tk.Text(tab2, wrap="word", width=60 * scale_factor, height=20 * scale_factor, font=default_font)
output_text2.pack(padx=5 * scale_factor, pady=5 * scale_factor)

output_text3 = tk.Text(tab3, wrap="word", width=60 * scale_factor, height=20 * scale_factor, font=default_font)
output_text3.pack(padx=5 * scale_factor, pady=5 * scale_factor)

# Port Scanner tab
target_entry = create_label_entry(tab1, "Target:", 0)
start_port_entry = create_label_entry(tab1, "Start Port:", 1)
end_port_entry = create_label_entry(tab1, "End Port:", 2)

scan_button = ttk.Button(tab1, text="Scan", command=lambda: threading.Thread(target=port_scanner, args=(progress_bar(tab1), output_text1)).start())
scan_button.grid(column=1, row=3, padx=5 * scale_factor, pady=5 * scale_factor)

# Network Scanner tab
ip_entry = create_label_entry(tab2, "IP Range:", 0)

scan_button = ttk.Button(tab2, text="Scan", command=lambda: threading.Thread(target=network_scanner, args=(progress_bar(tab2), output_text2)).start())
scan_button.grid(column=1, row=1, padx= 5 * scale_factor, pady=5 * scale_factor)

# Packet Analyzer tab
interface_var = tk.StringVar(tab3)
interface_var.set(get_available_interfaces()[0])
interface_label = ttk.Label(tab3, text="Interface:")
interface_label.grid(column=0, row=0, padx=5 * scale_factor, pady=5 * scale_factor)

interface_dropdown = ttk.OptionMenu(tab3, interface_var, *get_available_interfaces())
interface_dropdown.grid(column=1, row=0, padx=5 * scale_factor, pady=5 * scale_factor)

filter_entry = create_label_entry(tab3, "Filter:", 1)
filter_entry.insert(0, "tcp")  # Default filter to TCP packets

analyze_button = ttk.Button(tab3, text="Analyze", command=lambda: threading.Thread(target=start_packet_analyzer, args=(progress_bar(tab3), output_text3)).start())
analyze_button.grid(column=1, row=2, padx=5 * scale_factor, pady=5 * scale_factor)

# Run the GUI
window.mainloop()