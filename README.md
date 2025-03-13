📜 README.md
markdown
Copy
Edit
# 📡 Network Traffic Analyzer & Visualizer

This project analyzes network traffic from a `.pcap` file using **Scapy** and visualizes key insights with **Matplotlib**.  
It helps in understanding packet distribution, source activity, and protocol usage.

---

## 📂 **Project Structure**
📦 network-traffic-analyzer │-- 📂 logs/ # Directory to store captured .pcap files │-- ├── sniffed_packets.pcap # Sample pcap file (replace with your own) │ │-- 📜 visualize_pcap.py # Python script to analyze & visualize network traffic │-- 📜 README.md # Project documentation (this file) │-- 📜 requirements.txt # Dependencies list

yaml
Copy
Edit

---

## 🛠️ **Installation**
### 1️⃣ **Clone the Repository**
```bash
git clone https://github.com/your-username/network-traffic-analyzer.git
cd network-traffic-analyzer
2️⃣ Install Dependencies
bash
Copy
Edit
pip install -r requirements.txt
3️⃣ Prepare a .pcap File
Capture network packets using Wireshark or tcpdump and save them as logs/sniffed_packets.pcap.
Alternatively, use any .pcap file you have.
🚀 Usage
Run the script to visualize network traffic:

bash
Copy
Edit
python visualize_pcap.py
📜 File Descriptions
1️⃣ visualize_pcap.py (Main Script)
Reads network packets from logs/sniffed_packets.pcap
Extracts useful data such as timestamps, packet sizes, protocol types, and source IPs
Generates 4 key visualizations:
📊 Packet Frequency Over Time (Histogram)
🎭 Packet Size Distribution
🖧 Protocol Usage (Pie Chart)
🌍 Top Source IPs (Bar Graph)
2️⃣ logs/sniffed_packets.pcap (Packet Capture File)
Stores captured network traffic data.
Replace with your own .pcap file.
3️⃣ requirements.txt (Dependencies)
Contains the required Python libraries:

nginx
Copy
Edit
scapy
matplotlib
📊 Visualizations
Visualization	Description
📊 Packet Frequency Over Time	Shows packet density over time
🎭 Packet Size Distribution	Helps analyze the size variation of packets
🖧 Protocol Usage (Pie Chart)	Displays percentage of TCP, UDP, ARP, etc.
🌍 Top Source IPs (Bar Graph)	Highlights most active senders
📜 Example Code for visualize_pcap.py
python
Copy
Edit
import matplotlib.pyplot as plt
from scapy.all import rdpcap, IP, TCP, UDP, ARP

# Load PCAP file
packets = rdpcap("logs/sniffed_packets.pcap")

# Extract data
timestamps = [pkt.time for pkt in packets]
packet_sizes = [len(pkt) for pkt in packets]
protocols = {"TCP": 0, "UDP": 0, "ARP": 0, "Other": 0}
source_ips = {}

# Analyze packets
for pkt in packets:
    if IP in pkt:
        src_ip = pkt[IP].src
        source_ips[src_ip] = source_ips.get(src_ip, 0) + 1

        if TCP in pkt:
            protocols["TCP"] += 1
        elif UDP in pkt:
            protocols["UDP"] += 1
        else:
            protocols["Other"] += 1
    elif ARP in pkt:
        protocols["ARP"] += 1

# Plot Packet Frequency Over Time
plt.figure(figsize=(8, 5))
plt.hist(timestamps, bins=10, edgecolor="black")
plt.xlabel("Time")
plt.ylabel("Packet Count")
plt.title("📊 Packet Frequency Over Time")
plt.show()

# Plot Packet Size Distribution
plt.figure(figsize=(8, 5))
plt.hist(packet_sizes, bins=15, color="purple", edgecolor="black")
plt.xlabel("Packet Size (Bytes)")
plt.ylabel("Count")
plt.title("🎭 Packet Size Distribution")
plt.show()

# Plot Protocol Usage
plt.figure(figsize=(7, 7))
plt.pie(protocols.values(), labels=protocols.keys(), autopct="%1.1f%%", colors=["red", "blue", "green", "gray"])
plt.title("🖧 Protocol Usage")
plt.show()

# Plot Top 5 Source IPs
top_ips = sorted(source_ips.items(), key=lambda x: x[1], reverse=True)[:5]
plt.figure(figsize=(8, 5))
plt.bar([ip[0] for ip in top_ips], [ip[1] for ip in top_ips], color="orange")
plt.xlabel("Source IP")
plt.ylabel("Packet Count")
plt.title("🌍 Top 5 Source IPs")
plt.xticks(rotation=30)
plt.show()
🏗 Future Enhancements
🚨 Suspicious IP detection
📈 Anomaly detection using ML
🌐 Live packet capture visualization
🤝 Contributing
Fork the repo, add features, and submit a Pull Request! 🚀
👨‍💻 Author: [Your Name]
📧 Contact: your.email@example.com
🌐 Website: yourwebsite.com

yaml
Copy
Edit

---

### **📌 Instructions to Commit the File**
1️⃣ Copy the above code.  
2️⃣ Create a **README.md** file in your project folder.  
3️⃣ Paste the content and **save the file**.  
4️⃣ Commit and push using:
```bash
git add README.md
git commit -m "Added project documentation"
git push origin main
