import sys
import pyshark
import nmap
from PyQt5.QtCore import Qt, pyqtSignal, QThread, QObject, pyqtSlot
from PyQt5.QtWidgets import QApplication, QMainWindow, QTextEdit, QPushButton, QVBoxLayout, QWidget, QProgressBar, QSizePolicy
from PyQt5.QtGui import QFont

class NetworkScanner(QObject):
    """A class for performing network scans using Pyshark."""
    progress_callback = pyqtSignal(int)

    def __init__(self, interface='eth0'):
        """Initialize the NetworkScanner instance with the specified interface."""
        super().__init__()
        self.interface = interface

    def start_network_scan(self, packet_count=10):
        """Start a network scan using Pyshark and return the captured packets."""
        try:
            packets = []
            capture = pyshark.LiveCapture(interface=self.interface)
            for i, packet in enumerate(capture.sniff_continuously(packet_count=packet_count)):
                packets.append(packet)
                self.progress_callback.emit(int((i + 1) / packet_count * 100))
                if i + 1 >= packet_count:
                    break
            capture.close()
            return packets
        except pyshark.capture.capture.TSharkCrashException as e:
            print(f"Error capturing packets: {e}")
            return []

class PortScanner(QObject):
    """A class for performing port scans using nmap."""
    progress_callback = pyqtSignal(int)

    def __init__(self):
        """Initialize the PortScanner instance with the default target."""
        super().__init__()
        self.target = 'localhost'

    def start_port_scan(self):
        """Start a port scan using nmap and return a list of ports and their state."""
        open_ports = []
        port_scanner = nmap.PortScanner()
        result = port_scanner.scan(self.target, arguments='-p 1-65535')
        total_ports = sum(len(result['scan'][host]['tcp']) for host in result['scan'] if 'tcp' in result['scan'][host])
        scanned_ports = 0
        for host in result['scan']:
            if 'tcp' in result['scan'][host]:
                ports = result['scan'][host]['tcp']
                for port in ports:
                    if result['scan'][host]['tcp'][port]['state'] == 'open':
                        open_ports.append(f"Port {port} is open")
                    scanned_ports += 1
                    self.progress_callback.emit(int((scanned_ports / total_ports) * 100))
        return open_ports

class MainWindow(QMainWindow):
    """The main window of the application."""
    def __init__(self):
        """Initialize the MainWindow instance with the GUI elements and scanners."""
        super().__init__()

        self.setWindowTitle("Network and Port Scanner")
        self.setMinimumSize(600, 400)

        self.text_area = QTextEdit(self)
        self.text_area.setReadOnly(True)
        self.text_area.setFont(QFont("Monospace", 10))
        self.scan_network_button = QPushButton("Scan Network", self)
        self.scan_ports_button = QPushButton("Scan Ports", self)
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setAlignment(Qt.AlignCenter)
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setVisible(False)

        layout = QVBoxLayout()
        layout.addWidget(self.text_area)
        layout.addWidget(self.scan_network_button)
        layout.addWidget(self.scan_ports_button)
        layout.addWidget(self.progress_bar)

        widget = QWidget()
        widget.setLayout(layout)
        self.setCentralWidget(widget)

        self.network_scanner = NetworkScanner()
        self.port_scanner = PortScanner()

        self.scan_network_button.clicked.connect(self.start_network_scan)
        self.scan_ports_button.clicked.connect(self.start_port_scan)

    @pyqtSlot()
    def start_network_scan(self):
        """Start a network scan and display the captured packets in the text area."""
        self.text_area.clear()
        self.text_area.append("Starting network scan...")
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(True)
        self.network_thread = NetworkThread(self.network_scanner)
        self.network_thread.progress_callback.connect(self.update_progress_bar)
        self.network_thread.result_callback.connect(self.display_packets)
        self.network_thread.finished.connect(self.network_thread.deleteLater)
        self.network_thread.start()

    @pyqtSlot()
    def start_port_scan(self):
        """Start a port scan and display the open ports in the text area."""
        self.text_area.clear()
        self.text_area.append("Starting port scan...")
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(True)
        self.port_thread = PortThread(self.port_scanner)
        self.port_thread.progress_callback.connect(self.update_progress_bar)
        self.port_thread.result_callback.connect(self.display_ports)
        self.port_thread.finished.connect(self.port_thread.deleteLater)
        self.port_thread.start()

    @pyqtSlot(int)
    def update_progress_bar(self, value):
        """Update the progress bar value."""
        self.progress_bar.setValue(value)

    @pyqtSlot(list)
    def display_packets(self, packets):
        """Display the captured packets in the text area."""
        for packet in packets:
            self.text_area.append(str(packet))

    @pyqtSlot(list)
    def display_ports(self, ports):
        """Display the open ports in the text area."""
        for port in ports:
            self.text_area.append(port)


class NetworkThread(QThread):
    """A thread for running the network scan."""
    progress_callback = pyqtSignal(int)
    result_callback = pyqtSignal(list)

    def __init__(self, network_scanner):
        super().__init__()
        self.network_scanner = network_scanner

    def run(self):
        packets = self.network_scanner.start_network_scan()
        self.result_callback.emit(packets)

class PortThread(QThread):
    """A thread for running the port scan."""
    progress_callback = pyqtSignal(int)
    result_callback = pyqtSignal(list)

    def __init__(self, port_scanner):
        super().__init__()
        self.port_scanner = port_scanner

    def run(self):
        ports = self.port_scanner.start_port_scan()
        self.result_callback.emit(ports)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
