# 🔐 Real-Time Packet Sniffer with GUI | Python IDS Project

A real-time **Intrusion Detection System (IDS)** built using **Python**, featuring a **Tkinter GUI**, **live traffic graph**, **packet logging**, and **anomaly-based alerts** using `IsolationForest`.

---

## 📌 Features

- ✅ Real-time packet sniffing using Scapy
- ✅ GUI built with Tkinter (clean layout + controls)
- ✅ Protocol filter: TCP, UDP, ICMP, or ALL
- ✅ Live chart of packet sizes using Matplotlib
- ✅ Alerts for suspicious packets using anomaly detection
- ✅ Packet logging to `packet_log.txt`

---

## 🖥 GUI Preview

![image](https://github.com/user-attachments/assets/3117ced8-2a4f-4cca-ad0a-a8bf02f09348)


---

## 🛠 Technologies Used

| Component      | Library         |
|----------------|-----------------|
| Packet Capture | `scapy`         |
| GUI            | `tkinter`, `ttk`|
| Chart/Plot     | `matplotlib`    |
| Detection      | `scikit-learn` (IsolationForest) |
| Logging        | Plain `.txt` file |

---

## 🚀 How to Run

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/packet-sniffer-ids-gui.git
cd packet-sniffer-ids-gui
