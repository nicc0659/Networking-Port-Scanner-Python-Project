import pyshark
import nmap
from threading import Thread
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.progressbar import ProgressBar
from kivy.clock import Clock

class NetworkScanner:
    """A class for performing network scans using Pyshark."""
    def __init__(self, interface='eth0'):
        self.interface = interface

    def start_network_scan(self, packet_count=10):
        packets = []
        capture = pyshark.LiveCapture(interface=self.interface)
        for i, packet in enumerate(capture.sniff_continuously(packet_count=packet_count)):
            packets.append(packet)
            if i + 1 >= packet_count:
                break
        capture.close()
        return packets


class NetworkThread(Thread):
    """A thread for running the network scan."""
    def __init__(self, network_scanner, result_callback):
        super().__init__()
        self.network_scanner = network_scanner
        self.result_callback = result_callback

    def run(self):
        packets = self.network_scanner.start_network_scan()
        Clock.schedule_once(lambda dt: self.result_callback(packets))


class MainWindow(BoxLayout):
    """Main application window."""
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'vertical'
        self.padding = 10
        self.spacing = 10

        self.network_scanner = NetworkScanner()

        self.interface_input = TextInput(text='eth0')
        self.packet_count_input = TextInput(text='10')

        self.scan_button = Button(text='Start Network Scan', size_hint=(None, None), size=(200, 50))
        self.scan_button.bind(on_press=self.start_network_scan)

        self.scan_result = BoxLayout(orientation='vertical', spacing=5)
        self.progress_bar = ProgressBar(max=100, size_hint=(None, None), height=50)

        self.add_widget(Label(text='Interface:'))
        self.add_widget(self.interface_input)
        self.add_widget(Label(text='Packet Count:'))
        self.add_widget(self.packet_count_input)
        self.add_widget(self.scan_button)
        self.add_widget(self.progress_bar)
        self.add_widget(self.scan_result)

    def start_network_scan(self, instance):
        interface = self.interface_input.text
        packet_count = int(self.packet_count_input.text)
        self.scan_result.clear_widgets()

        network_thread = NetworkThread(self.network_scanner, self.on_network_scan_complete)
        network_thread.start()

        self.scan_button.disabled = True
        self.progress_bar.value = 0

    def on_network_scan_complete(self, packets):
        for packet in packets:
            self.scan_result.add_widget(Label(text=str(packet)))
            self.progress_bar.value += 1
        self.scan_button.disabled = False

class NetworkScannerApp(App):
    """The Kivy application class."""
    def build(self):
        return MainWindow()

if __name__ == '__main__':
    NetworkScannerApp().run()
