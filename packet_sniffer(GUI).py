import tkinter as tk
from tkinter import scrolledtext
import socket
import struct
import threading
import textwrap

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t - '
DATA_TAB_2 = '\t\t - '
DATA_TAB_3 = '\t\t\t - '
DATA_TAB_4 = '\t\t\t\t - '


class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        self.root.geometry("800x600")

        self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack()

        self.stop_button = tk.Button(root, text="Stop Sniffing", command=self.stop_sniffing)
        self.stop_button.pack()

        self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=100, height=30)
        self.text_area.pack()

        self.sniffing = False

    def start_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            self.sniffing_thread = threading.Thread(target=self.sniff_packets)
            self.sniffing_thread.start()

    def stop_sniffing(self):
        if self.sniffing:
            self.sniffing = False
            self.sniffing_thread.join()

    def sniff_packets(self):
        HOST = socket.gethostbyname(socket.gethostname())
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        conn.bind((HOST, 0))
        conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        while self.sniffing:
            raw_data, addr = conn.recvfrom(65536)
            dest_mac, src_mac, eth_pro, data = self.ethernet_frame(raw_data)
            self.print_to_gui('\nEthernet Frame:')
            self.print_to_gui(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_pro))

            if eth_pro == 8:  # IPv4
                (version, header_length, ttl, proto, src, target, data) = self.ipv4_packet(data)
                self.print_to_gui(TAB_1 + 'IPv4 Packet:')
                self.print_to_gui(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
                self.print_to_gui(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

                if proto == 1:
                    icmp_type, code, checksum, data = self.icmp_packet(data)
                    self.print_to_gui(TAB_1 + 'ICMP Packet:')
                    self.print_to_gui(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                    self.print_to_gui(TAB_2 + 'Data:')
                    self.print_to_gui(self.format_multi_line(DATA_TAB_3, data))

                elif proto == 6:
                    src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_sin, flag_fin, data = self.tcp_segment(
                        data)
                    self.print_to_gui(TAB_1 + 'TCP Segment:')
                    self.print_to_gui(TAB_2 + 'Source Port: {}, Destination port: {}'.format(src_port, dest_port))
                    self.print_to_gui(TAB_2 + 'Sequence: {}, Acknowledgement: {}'.format(sequence, acknowledgement))
                    self.print_to_gui(TAB_2 + 'Flags:')
                    self.print_to_gui(
                        TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack,
                                                                                              flag_psh, flag_rst,
                                                                                              flag_sin, flag_fin))
                    self.print_to_gui(TAB_2 + 'Data:')
                    self.print_to_gui(self.format_multi_line(DATA_TAB_3, data))

                elif proto == 17:
                    src_port, dest_port, size, data = self.udp_segment(data)
                    self.print_to_gui(TAB_1 + 'UDP Segment:')
                    self.print_to_gui(
                        TAB_2 + 'Source Port: {}, Destination port: {}, Length: {}'.format(src_port, dest_port, size))
                    self.print_to_gui(TAB_2 + 'Data:')
                    self.print_to_gui(self.format_multi_line(DATA_TAB_3, data))

                else:
                    self.print_to_gui(TAB_1 + 'Data:')
                    self.print_to_gui(self.format_multi_line(DATA_TAB_2, data))

            else:
                self.print_to_gui('Data:')
                self.print_to_gui(self.format_multi_line(DATA_TAB_1, data))

    def print_to_gui(self, text):
        self.text_area.insert(tk.END, text + '\n')
        self.text_area.see(tk.END)

    def ethernet_frame(self, data):
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
        return self.get_mac_addr(dest_mac), self.get_mac_addr(src_mac), socket.htons(proto), data[14:]

    def get_mac_addr(self, bytes_addr):
        bytes_str = map('{:02x}'.format, bytes_addr)
        return ':'.join(bytes_str).upper()

    def ipv4_packet(self, data):
        version_header_length = data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4
        ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        return version, header_length, ttl, proto, self.ipv4(src), self.ipv4(target), data[header_length:]

    def ipv4(self, addr):
        return '.'.join(map(str, addr))

    def icmp_packet(self, data):
        icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
        return icmp_type, code, checksum, data[4:]

    def tcp_segment(self, data):
        (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H',
                                                                                                data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        flag_urg = (offset_reserved_flags & 32) >> 5
        flag_ack = (offset_reserved_flags & 16) >> 4
        flag_psh = (offset_reserved_flags & 8) >> 3
        flag_rst = (offset_reserved_flags & 4) >> 2
        flag_sin = (offset_reserved_flags & 2) >> 1
        flag_fin = (offset_reserved_flags & 1)
        return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_sin, flag_fin, data[
                                                                                                                           offset:]

    def udp_segment(self, data):
        src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
        return src_port, dest_port, size, data[:8]

    def format_multi_line(self, prefix, string, size=80):
        size -= len(prefix)
        if isinstance(string, bytes):
            string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
            if size % 2:
                size -= 1
        return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
