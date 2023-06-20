import sys 
from PyQt5.QtWidgets import QApplication, QLabel, QMainWindow, QTextEdit, QLineEdit, QPushButton, QComboBox, QProgressBar, QVBoxLayout, QHBoxLayout, QWidget, QTabWidget
from PyQt5.QtCore import Qt, QThread, pyqtSignal
import nmap
from scapy.all import ARP, Ether, srp
import pyshark
import socket

# [likegeeks.com](https://likegeeks.com/pyqt5-tutorial/)
class PortScannerThread(QThread):
    progress = pyqtSignal()
    scanned = pyqtSignal(str)

    def __init__(self, target, start_port, end_port):
        super().__init__()
        self.target = target
        self.start_port = start_port
        self.end_port = end_port

    def run(self):
        nm = nmap.PortScanner()
        ports = f"{self.start_port}-{self.end_port}"
        nm.scan(hosts=self.target, ports=ports, arguments='-Pn')

        for host in nm.all_hosts():
            self.scanned.emit(f"Host: {host} ({nm[host].hostname()})\n")
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    self.scanned.emit(f"Port: {port}, State: {nm[host][proto][port]['state']}\n")

        self.progress.emit()

class NetworkScannerThread(QThread):
    progress = pyqtSignal()
    scanned = pyqtSignal(str)

    def __init__(self, ip_range):
        super().__init__()
        self.ip_range = ip_range

    def run(self):
        arp_request = ARP(pdst=self.ip_range)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered, _ = srp(arp_request_broadcast, timeout=1, verbose=False)

        for sent, received in answered:
            self.scanned.emit(f"IP: {received.psrc}, MAC: {received.hwsrc}\n")

        self.progress.emit()

class PacketAnalyzerThread(QThread):
    progress = pyqtSignal()
    analyzed = pyqtSignal(str)

    def __init__(self, interface, filter_text):
        super().__init__()
        self.interface = interface
        self.filter_text = filter_text

    def run(self):
        capture = pyshark.LiveCapture(interface=self.interface, display_filter=self.filter_text)
        capture.apply_on_packets(lambda packet: self.analyzed.emit(f"{packet}\n"), timeout=10)
        self.progress.emit()

class NetworkTool(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Network Tool")

        # Main layout 
        main_layout = QVBoxLayout()

        # Create tabs
        self.tab_widget = QTabWidget()
        self.port_scanner_tab = QWidget()
        self.network_scanner_tab = QWidget()
        self.packet_analyzer_tab = QWidget()

        self.tab_widget.addTab(self.port_scanner_tab, "Port Scanner")
        self.tab_widget.addTab(self.network_scanner_tab, "Network Scanner")
        self.tab_widget.addTab(self.packet_analyzer_tab, "Packet Analyzer")

        main_layout.addWidget(self.tab_widget)

        # Port Scanner tab
        self.setup_port_scanner_tab()

        # Network Scanner tab
        self.setup_network_scanner_tab()   

        # Packet Analyzer tab
        self.setup_packet_analyzer_tab()

        # Output text 
        output_label = QLabel("Output:")
        main_layout.addWidget(output_label)
        self.output_text = QTextEdit()
        main_layout.addWidget(self.output_text)

        central_widget = QWidget()
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

    def setup_port_scanner_tab(self):
        layout = QVBoxLayout()
        
        target_label = QLabel("Target:")
        layout.addWidget(target_label)
        self.target_entry = QLineEdit()
        layout.addWidget(self.target_entry)
        
        start_port_label = QLabel("Start Port:")
        layout.addWidget(start_port_label) 
        self.start_port_entry = QLineEdit()
        layout.addWidget(self.start_port_entry)
        
        end_port_label = QLabel("End Port:")
        layout.addWidget(end_port_label)
        self.end_port_entry = QLineEdit()
        layout.addWidget(self.end_port_entry)

        scan_button = QPushButton("Scan")
        layout.addWidget(scan_button)  

        progress_label = QLabel("Progress:")  
        layout.addWidget(progress_label)
        self.port_scanner_progress = QProgressBar()
        layout.addWidget(self.port_scanner_progress)

        scan_button.clicked.connect(self.start_port_scan)

        self.port_scanner_tab.setLayout(layout)
        
    def setup_network_scanner_tab(self):             
        layout = QVBoxLayout()          
        ip_range_label = QLabel("IP Range:")
        layout.addWidget(ip_range_label)
        self.ip_entry = QLineEdit()
        layout.addWidget(self.ip_entry)
        
        scan_button = QPushButton("Scan")
        layout.addWidget(scan_button)  

        progress_label = QLabel("Progress:")  
        layout.addWidget(progress_label)  
        self.network_scanner_progress = QProgressBar()
        layout.addWidget(self.network_scanner_progress)

        scan_button.clicked.connect(self.start_network_scan)

        self.network_scanner_tab.setLayout(layout)

    def setup_packet_analyzer_tab(self):
        layout = QVBoxLayout()  
        
        interface_label = QLabel("Interface:")
        layout.addWidget(interface_label)
        self.interface_combobox = QComboBox()
        layout.addWidget(self.interface_combobox)

        filter_label = QLabel("Filter:")
        layout.addWidget(filter_label) 
        self.filter_entry = QLineEdit()
        layout.addWidget(self.filter_entry)
        
        analyze_button = QPushButton("Analyze")
        layout.addWidget(analyze_button)  

        progress_label = QLabel("Progress:")  
        layout.addWidget(progress_label)
        self.packet_analyzer_progress = QProgressBar()
        layout.addWidget(self.packet_analyzer_progress)

        analyze_button.clicked.connect(self.start_packet_analysis)

        self.packet_analyzer_tab.setLayout(layout)

    def start_port_scan(self):
        target = self.target_entry.text()
        start_port = int(self.start_port_entry.text())
        end_port = int(self.end_port_entry.text())

        self.port_scanner_thread = PortScannerThread(target, start_port, end_port)
        self.port_scanner_thread.scanned.connect(self.output_text.append)
        self.port_scanner_thread.progress.connect(lambda: self.port_scanner_progress.setValue(50))
        self.port_scanner_thread.start()

    def start_network_scan(self):
        ip_range = self.ip_entry.text()

        self.network_scanner_thread = NetworkScannerThread(ip_range)
        self.network_scanner_thread.scanned.connect(self.output_text.append)
        self.network_scanner_thread.progress.connect(lambda: self.network_scanner_progress.setValue(50))
        self.network_scanner_thread.start()

    def start_packet_analysis(self):
        interface = self.interface_combobox.currentText()
        filter_text = self.filter_entry.text()

        self.packet_analyzer_thread = PacketAnalyzerThread(interface, filter_text)
        self.packet_analyzer_thread.analyzed.connect(self.output_text.append)
        self.packet_analyzer_thread.progress.connect(lambda: self.packet_analyzer_progress.setValue(50))
        self.packet_analyzer_thread.start()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NetworkTool()
    window.show()
    sys.exit(app.exec_())