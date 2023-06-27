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
window.title("Network & Port Scanning Tool")

# Upscale factor
scale_factor = 2

# Create stop events for each thread
stop_event_port_scan = threading.Event()
stop_event_network_scan = threading.Event()
stop_event_packet_analyzer_scan = threading.Event()

capture = None  # Declare capture at a global scope

# Adjust font size for all widgets
default_font = tkFont.nametofont("TkDefaultFont")
default_font.configure(size=int(default_font['size'] * scale_factor))

# Port scanner function
def port_scanner(progress, stop_event):
    stop_event.clear()  # Reset the stop event at start
    nm = nmap.PortScanner()
    target = target_entry.get()
    start_port = int(start_port_entry.get())
    end_port = int(end_port_entry.get())
    for port in range(start_port, end_port + 1):
        if stop_event.is_set():
            stop_event.clear()  # Reset the stop event after breaking too
            break
        nm.scan(hosts=target, ports=str(port), arguments='-sS -Pn --host-timeout 200ms')
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    port_output_text.insert(tk.END, f"Port: {port}, State: {nm[host][proto][port]['state']}\n")
                    port_output_text.update_idletasks()
    progress.stop()


# Network scanner function
def network_scanner(progress, stop_event):
    stop_event.clear()  # Reset the stop event at start
    ip_range = ip_entry.get()
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered, _ = srp(arp_request_broadcast, timeout=1, verbose=True)

    for sent, received in answered:
        if stop_event.is_set():
            stop_event.clear()  # Reset the stop event after breaking too
            break
        network_output_text.insert(tk.END, f"IP: {received.psrc}, MAC: {received.hwsrc}\n")
        network_output_text.update_idletasks()
        
    progress.stop()

def start_packet_analyzer(progress, stop_event):
    stop_event.clear()  # Reset the stop event at start
    global capture
    interface = interface_var.get()
    filter_text = filter_entry.get().strip()  # Fetch filter from the Entry

    capture = pyshark.LiveCapture(interface=interface, bpf_filter=filter_text)  # Using bpf_filter
    packets = []  # To store captured packets
    capture_thread = threading.Thread(target=lambda: packets.extend(capture.sniff_continuously()))
    capture_thread.start()

    try:
        while capture_thread.is_alive():
            # Check stop event, break the loop if the stop event is set
            if stop_event.is_set():
                break
            # Insert captured packets to output text
            while packets:
                packet = packets.pop(0)
                packet_output_text.insert(tk.END, f"{packet}\n")
                packet_output_text.update_idletasks()
    finally:
        stop_event.clear()
        if capture:
            capture.close()
        progress.stop()


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

#output_text = tk.Text(window, wrap="word", width=60 * scale_factor, height=20 * scale_factor, font=default_font)
#output_text.pack(padx=5 * scale_factor, pady=5 * scale_factor)

# List of BPF filters for protocols
protocols = ['tcp', 'udp', 'arp', 'icmp', 'dns']
# Variable to hold the selected protocol
filter_var = tk.StringVar()
filter_var.set(protocols[0])  # Default value

# Create Protocol Dropdown replacing Filter text entry
filter_label = ttk.Label(tab3, text="Protocol:")
filter_label.grid(column=0, row=1, padx=5 * scale_factor, pady=5 * scale_factor)
filter_option_menu = ttk.OptionMenu(tab3, filter_var, *protocols)
filter_option_menu.grid(column=1, row=1, padx=5 * scale_factor, pady=5 * scale_factor)

# Create output text for each tab
port_output_text = tk.Text(tab1, wrap="word", width=60 * scale_factor, height=20 * scale_factor, font=default_font)
port_output_text.grid(column=0, row=5, padx=5 * scale_factor, pady=5 * scale_factor, columnspan=2)

network_output_text = tk.Text(tab2, wrap="word", width=60 * scale_factor, height=20 * scale_factor, font=default_font)
network_output_text.grid(column=0, row=5, padx=5 * scale_factor, pady=5 * scale_factor, columnspan=2)

packet_output_text = tk.Text(tab3, wrap="word", width=60 * scale_factor, height=20 * scale_factor, font=default_font)
packet_output_text.grid(column=0, row=5, padx=5 * scale_factor, pady=5 * scale_factor, columnspan=2)

# Port Scanner tab
target_entry = create_label_entry(tab1, "Target:", 0)
start_port_entry = create_label_entry(tab1, "Start Port:", 1)
end_port_entry = create_label_entry(tab1, "End Port:", 2)

scan_button_port_scan = ttk.Button(tab1, text="Scan", command=lambda: threading.Thread(target=port_scanner, args=(progress_bar(tab1), stop_event_port_scan)).start())
scan_button_port_scan.grid(column=1, row=3, padx=5 * scale_factor, pady=5 * scale_factor)

# Network Scanner tab
ip_entry = create_label_entry(tab2, "CIDR :", 0)

scan_button_network_scan = ttk.Button(tab2, text="Scan", command=lambda: threading.Thread(target=network_scanner, args=(progress_bar(tab2), stop_event_network_scan)).start())
scan_button_network_scan.grid(column=1, row=1, padx=5 * scale_factor, pady=5 * scale_factor)

# Packet Analyzer tab
interface_var = tk.StringVar()
interface_var.set(get_available_interfaces()[0])
interface_label = ttk.Label(tab3, text="Interface:")
interface_label.grid(column=0, row=0, padx=5 * scale_factor, pady=5 * scale_factor)
interface_option_menu = ttk.OptionMenu(tab3, interface_var, *get_available_interfaces())
interface_option_menu.grid(column=1, row=0, padx=5 * scale_factor, pady=5 * scale_factor)

filter_entry = create_label_entry(tab3, "Filter:", 2)
filter_entry.grid(column=1, row=2, padx=5 * scale_factor, pady=5 * scale_factor)

analyze_button_packet_analyzer = ttk.Button(tab3, text="Analyze", command=lambda: threading.Thread(target=start_packet_analyzer, args=(progress_bar(tab3), stop_event_packet_analyzer_scan)).start())
analyze_button_packet_analyzer.grid(column=1, row=3, padx=5 * scale_factor, pady=5 * scale_factor)

# Add stop buttons
stop_port_scan_button = ttk.Button(tab1, text="Stop", command= stop_event_port_scan.set)
stop_port_scan_button.grid(column=0, row=3, padx=5 * scale_factor, pady=5 * scale_factor)

stop_network_scan_button = ttk.Button(tab2, text="Stop", command= stop_event_network_scan.set)
stop_network_scan_button.grid(column=0, row=1, padx=5 * scale_factor, pady=5 * scale_factor)

stop_packet_analyzer_button = ttk.Button(tab3, text="Stop", command= stop_event_packet_analyzer_scan.set)
stop_packet_analyzer_button.grid(column=0, row=3, padx=5 * scale_factor, pady=5 * scale_factor)

window.mainloop()