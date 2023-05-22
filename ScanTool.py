import socket
import threading
import tkinter as tk
from tkinter import ttk

def portScanner(host):
    open_ports = []
    for port in range(1, 64535):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((host, port))
        if result == 0:
            logText.insert(tk.END, f'Port {port} is open\n')
            open_ports.append(port)
        else:
            logText.insert(tk.END, f'Port {port} is closed\n')
        logText.see(tk.END)
        sock.close()
        progressBar['value'] = port / 64535 * 100
        root.update_idletasks()
    return open_ports

def startScan():
    host = hostEntry.get()
    open_ports = portScanner(host)
    resultLabel['text'] = f'Open ports on {host}:\n' + '\n'.join(map(str, open_ports))

root = tk.Tk()
root.title('Port Scanner')

hostLabel = tk.Label(root, text='Host:')
hostLabel.pack()

hostEntry = tk.Entry(root)
hostEntry.pack()

scanButton = tk.Button(root, text='Start Scan', command=startScan)
scanButton.pack()

progressBar = ttk.Progressbar(root, orient='horizontal', length=200, mode='determinate')
progressBar.pack()

logFrame = tk.Frame(root)
logFrame.pack()

logText = tk.Text(logFrame, height=10)
logText.pack(side=tk.LEFT)

logScrollbar = tk.Scrollbar(logFrame)
logScrollbar.pack(side=tk.RIGHT, fill=tk.Y)

logText.config(yscrollcommand=logScrollbar.set)
logScrollbar.config(command=logText.yview)

resultLabel = tk.Label(root, text='')
resultLabel.pack()

root.mainloop()
