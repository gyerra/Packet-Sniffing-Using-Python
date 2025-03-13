📜 README.md
# 📡 Network Traffic Analyzer & Visualizer
This project analyzes network traffic from a `.pcap` file using **Scapy** and visualizes key insights with **Matplotlib**.  
It helps in understanding packet distribution, source activity, and protocol usage.

## 📂 **Project Structure**
📦 network-traffic-analyzer
│-- 📂 logs/                # Directory to store captured .pcap files
│   ├── sniffed_packets.pcap  # Sample pcap file (replace with your own)
│
│-- 📜 visualize_pcap.py     # Python script to analyze & visualize network traffic
│-- 📜 sniff_packets.py      # (Optional) Script to capture live network traffic and save it as a .pcap file
│-- 📜 requirements.txt      # Dependencies list
│-- 📜 README.md             # Project documentation (this file)


🛠️ **Installation**
1️⃣ **Clone the Repository**
git clone https://github.com/your-username/network-traffic-analyzer.git
cd network-traffic-analyzer
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

