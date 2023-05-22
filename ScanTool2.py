from kivy.lang import Builder
from kivymd.app import MDApp
from kivy.clock import Clock
from kivy.properties import StringProperty
from kivymd.app import MDApp
import threading
import socket

KV = """
BoxLayout:
    orientation: 'vertical'
    MDToolbar:
        title: 'Port Scanner'
    BoxLayout:
        orientation: 'horizontal'
        MDTextField:
            id: host
            hint_text: 'Host'
        MDRaisedButton:
            text: 'Start Scan'
            on_release: app.startScan()
    ScrollView:
        MDList:
            id: log_list
    MDSpinner:
        id: spinner
        size_hint: None, None
        size: dp(46), dp(46)
        pos_hint: {'center_x': .5, 'center_y': .5}
        active: False
"""

def portScanner(host, log_list, spinner):
    open_ports = []
    for port in range(1, 64535):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((host, port))
        if result == 0:
            log_list.add_widget(
                OneLineListItem(text=f'Port {port} is open')
            )
            open_ports.append(port)
        else:
            log_list.add_widget(
                OneLineListItem(text=f'Port {port} is closed')
            )
        sock.close()
    spinner.active = False

class PortScannerApp(MDApp):
    def build(self):
        return Builder.load_string(KV)

    def startScan(self):
        host = self.root.ids.host.text
        log_list = self.root.ids.log_list
        log_list.clear_widgets()
        spinner = self.root.ids.spinner
        spinner.active = True
        threading.Thread(target=portScanner, args=(host, log_list, spinner)).start()

PortScannerApp().run()
