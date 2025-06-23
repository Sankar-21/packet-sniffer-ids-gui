import tkinter as tk
from tkinter import ttk, messagebox
import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP
from sklearn.ensemble import IsolationForest
import numpy as np
import time
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

class ProfessionalSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Real-Time IDS - Packet Sniffer")
        self.root.geometry("1000x600")
        self.root.configure(bg="#f4f4f4")

        self.running = False
        self.packet_data = []
        self.packet_sizes = []
        self.timestamps = []
        self.protocol_filter = tk.StringVar(value="ALL")
        self.detector = IsolationForest(contamination=0.1)

        self.create_widgets()

    def create_widgets(self):
        # Header
        header = tk.Label(self.root, text="🚨 Intrusion Detection Dashboard", bg="#2c3e50", fg="white", font=("Helvetica", 18, "bold"), pady=10)
        header.pack(fill=tk.X)

        # Control Panel Frame
        control_frame = tk.Frame(self.root, bg="#ecf0f1", pady=10)
        control_frame.pack(fill=tk.X)

        ttk.Label(control_frame, text="Protocol:", background="#ecf0f1", font=("Segoe UI", 10)).pack(side=tk.LEFT, padx=10)
        ttk.Combobox(control_frame, textvariable=self.protocol_filter, values=["ALL", "TCP", "UDP", "ICMP"], width=10).pack(side=tk.LEFT)

        ttk.Button(control_frame, text="Start", command=self.start_sniffing).pack(side=tk.LEFT, padx=10)
        ttk.Button(control_frame, text="Stop", command=self.stop_sniffing).pack(side=tk.LEFT)

        # Main Output Frame
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Text area for packet logs
        self.output_text = tk.Text(main_frame, height=15, font=("Courier New", 10), bg="white")
        self.output_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Live Graph Area
        self.fig, self.ax = plt.subplots(figsize=(5, 3))
        self.canvas = FigureCanvasTkAgg(self.fig, master=main_frame)
        self.canvas.get_tk_widget().pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10)

        # Footer Status Bar
        self.status = tk.Label(self.root, text="Status: Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W, bg="#bdc3c7")
        self.status.pack(fill=tk.X, side=tk.BOTTOM)

    def start_sniffing(self):
        self.running = True
        self.packet_data = []
        self.packet_sizes = []
        self.timestamps = []
        self.status.config(text="Status: Sniffing...")
        threading.Thread(target=self.sniff).start()

    def stop_sniffing(self):
        self.running = False
        self.status.config(text="Status: Stopped")

    def sniff(self):
        sniff(prn=self.process_packet, store=False)

    def process_packet(self, packet):
        if not self.running or not packet.haslayer(IP):
            return

        # Protocol filtering
        selected = self.protocol_filter.get()
        if (selected == "TCP" and not packet.haslayer(TCP)) or \
           (selected == "UDP" and not packet.haslayer(UDP)) or \
           (selected == "ICMP" and not packet.haslayer(ICMP)):
            return

        src = packet[IP].src
        dst = packet[IP].dst
        size = len(packet)
        timestamp = time.strftime("%H:%M:%S")

        # Update output and log
        self.output_text.insert(tk.END, f"{timestamp} | {src} → {dst} | Size: {size} bytes\n")
        self.output_text.see(tk.END)

        with open("packet_log.txt", "a") as log:
            log.write(f"{timestamp},{src},{dst},{size}\n")

        # Update chart
        self.packet_data.append([size])
        self.packet_sizes.append(size)
        self.timestamps.append(timestamp)

        if len(self.packet_data) >= 20:
            data = np.array(self.packet_data[-20:])
            self.detector.fit(data)
            prediction = self.detector.predict([self.packet_data[-1]])
            if prediction[0] == -1:
                self.alert_popup(src, dst)

        self.update_chart()

    def update_chart(self):
        self.ax.clear()
        self.ax.plot(self.timestamps[-20:], self.packet_sizes[-20:], marker="o", linestyle='-', color='royalblue')
        self.ax.set_title("Live Packet Size", fontsize=10)
        self.ax.set_ylabel("Size (bytes)")
        self.ax.set_xlabel("Time")
        self.ax.grid(True, linestyle='--', alpha=0.6)
        self.fig.autofmt_xdate()
        self.canvas.draw()

    def alert_popup(self, src, dst):
        messagebox.showwarning("Suspicious Activity Detected", f"Source: {src}\nDestination: {dst}")
        self.status.config(text="Status: ALERT 🚨")

# Launch GUI
if __name__ == "__main__":
    root = tk.Tk()
    app = ProfessionalSnifferGUI(root)
    root.mainloop()
