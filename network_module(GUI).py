import scapy.all as scapy
import socket
import wmi
import tkinter as tk
from tkinter import ttk, messagebox
import ipaddress

def is_valid_ip(ip):
    try:
        ipaddress.ip_network(ip, strict=False)
        return True
    except ValueError:
        return False

def scan(ip, text_widget):
    if not is_valid_ip(ip):
        text_widget.insert(tk.END, "Invalid IP address or range. Please enter a valid IP range.\n")
        return

    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    results = []
    for element in answered_list:
        ip = element[1].psrc
        mac = element[1].hwsrc
        try:
            device_name = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            device_name = "Unknown"

        result = {"ip": ip, "mac": mac, "device_name": device_name}
        results.append(result)

    text_widget.delete("1.0", tk.END)
    text_widget.insert(tk.END, "IP Address\t\tMAC Address\t\t\tDevice Name\n")
    text_widget.insert(tk.END, "---------------------------------------------------------------\n")
    for result in results:
        text_widget.insert(tk.END, f"{result['ip']}\t\t{result['mac']}\t\t{result['device_name']}\n")


def update_ip_entry(choice, ip_entry):
    if choice == "Your IP":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        user_socket = s.getsockname()[0]
        user_socket = user_socket + "/24"
        s.close()
        ip_entry.config(state='normal')
        ip_entry.delete(0, tk.END)
        ip_entry.insert(0, user_socket)
        ip_entry.config(state='disabled')
    elif choice == "Router IP":
        wmi_obj = wmi.WMI()
        wmi_sql = "select IPAddress,DefaultIPGateway from Win32_NetworkAdapterConfiguration where IPEnabled=TRUE"
        wmi_out = wmi_obj.query(wmi_sql)

        for dev in wmi_out:
            web_socket = dev.DefaultIPGateway[0]

        web_socket = web_socket + "/24"
        ip_entry.config(state='normal')
        ip_entry.delete(0, tk.END)
        ip_entry.insert(0, web_socket)
        ip_entry.config(state='disabled')
    elif choice == "Custom IP Range":
        ip_entry.config(state='normal')
        ip_entry.delete(0, tk.END)
        ip_entry.insert(0, "Enter IP range (e.g., 192.168.1.1/24)")


def main():
    def start_scan():
        choice = combo.get()
        if choice == "Your IP" or choice == "Router IP":
            ip_range = ip_entry.get()
            scan(ip_range, text)
        elif choice == "Custom IP Range":
            ip_range = ip_entry.get()
            if ip_range and ip_range != "Enter IP range (e.g., 192.168.1.1/24)":
                scan(ip_range, text)
            else:
                messagebox.showerror("Error", "Please enter a valid IP range.")
        else:
            messagebox.showerror("Error", "Invalid choice. Please try again.")

    root = tk.Tk()
    root.title("Network Scanner")

    frame = ttk.Frame(root, padding="10")
    frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

    options = ["Your IP", "Router IP", "Custom IP Range"]
    combo = ttk.Combobox(frame, values=options)
    combo.set("Select Scan Type")
    combo.grid(row=0, column=0, pady=10, padx=5)

    ip_entry = ttk.Entry(frame, width=30)
    ip_entry.grid(row=0, column=1, pady=10, padx=5)

    combo.bind("<<ComboboxSelected>>", lambda event: update_ip_entry(combo.get(), ip_entry))

    scan_button = ttk.Button(frame, text="Scan", command=start_scan)
    scan_button.grid(row=0, column=2, pady=10, padx=5)

    text = tk.Text(frame, height=15, width=80)
    text.grid(row=1, column=0, columnspan=3, pady=10, padx=5)

    root.mainloop()


if __name__ == "__main__":
    main()
