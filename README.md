📜 README.md
# 📡 Network Traffic Analyzer & Visualizer
This project analyzes network traffic from a `.pcap` file using **Scapy** and visualizes key insights with **Matplotlib**.  
It helps in understanding packet distribution, source activity, and protocol usage.

## 📂 **Project Structure**
📦 PACKET_SNIFFER
│-- 📂 logs/                 # Directory to store captured packet data
│   ├── sniffed_packets.pcap  # Captured network traffic in PCAP format
│   ├── sniffed_packets.txt   # Extracted packet details in text format
│
│-- 📜 main.py                # Main script to run the packet sniffer
│-- 📜 analyze_pcap.py        # Script to analyze the pcap file
│-- 📜 visualize_pcap.py      # Script to visualize network traffic from pcap file
│-- 📜 packet_utils.py        # Utility functions for packet processing
│-- 📜 requirements.txt       # Dependencies list
│-- 📜 Figure_1.png           # Sample visualization output
│-- 📂 __pycache__/           # Python cache directory (auto-generated)



🛠️ **Installation**
1️⃣ **Clone the Repository**
git clone https://github.com/gyerra/Packet-Sniffing-Using-Python.git
cd packet-sniffer
2️⃣ Install Dependencies
pip install -r requirements.txt
3️⃣ Prepare a .pcap File
Capture network packets using Wireshark or tcpdump and save them as logs/sniffed_packets.pcap.
Alternatively, use any .pcap file you have.
🚀 Usage
Run the script to visualize network traffic:
python visualize_pcap.py

**File Descriptions**
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
scapy
matplotlib

**Visualizations**
Visualization	Description
📊 Packet Frequency Over Time	Shows packet density over time
🎭 Packet Size Distribution	Helps analyze the size variation of packets
🖧 Protocol Usage (Pie Chart)	Displays percentage of TCP, UDP, ARP, etc.
🌍 Top Source IPs (Bar Graph)	Highlights most active senders

**Future Enhancements**
🚨 Suspicious IP detection
📈 Anomaly detection using ML
🌐 Live packet capture visualization

