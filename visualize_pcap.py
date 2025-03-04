import matplotlib.pyplot as plt
from scapy.all import rdpcap

packets = rdpcap("logs/sniffed_packets.pcap")

# Extract timestamps
timestamps = [packet.time for packet in packets]

# Plot histogram
plt.hist(timestamps, bins=10, edgecolor="black")
plt.xlabel("Time")
plt.ylabel("Packet Count")
plt.title("Packet Frequency Over Time")
plt.show()
