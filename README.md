
<h4 align="center"> Intrusion Detection System</h4>

Implementation:
  For this part I use the pcap library to read packets from a .pcapng file using pcap_open_offline()
  These packets are then passed through the pcap_loop() function to the packetHandler() function.
  The packetHandler() function reads the source IP, destination IP, source port and destination port
  from the packet headers.
  The packetHandler() function then passes this information to the raise_alerts() function.
  The raise_alerts() function reads from alerts.txt, which contains the rules, and compares 
  the data it recieved to the data specified in the rules.
  If any packets match data, it raises an alert.

How it should be executed:
  The .txt and .pcapng files are currently defined in IDS.h so the program can
  be executed by simply running the executable.
  ```bash
  ./IDS
  ```



