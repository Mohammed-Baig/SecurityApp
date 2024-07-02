# SecurityApp

## Security application capable of:
- Scanning system for potential malware
- track and analyze local network activity such as packet protocols and message content/materia
- scan website to determine whether it's safe or not
- scan router to see who's connected
- analyze password security, such as how safe it is and any possible improvements you can make

Users can choose whether they'd like to work in the terminal or use the tkinter gui

## Note:
- For the network module you will need to install npcap. You can get it from: https://npcap.com/#download
- For the online vulnerability scanner, you may need a google safe browsing and urlscan api key. You can find them from https://developers.google.com/safe-browsing/v4/get-started and https://urlscan.io/docs/api/ resepectively


## TO DO:
Packet sniffer:
1) Implement message decoder

local vulnerability checker:
1) Heuristic Based observation
2) Implement future quarantining
3) Implement Virustotal connectivity

network module:
1) Remove reliance on npcap
2) Implement AbuseIPDB connectivity
3) Implement Virustotal connectivity

online vulnerability:
1) Implement Virustotal connectivity


