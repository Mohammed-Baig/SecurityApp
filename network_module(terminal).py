import scapy.all as scapy
import socket
import wmi

def scan(ip):
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
            device_name = None

        result = {"ip": ip, "mac": mac, "device_name": device_name}
        results.append(result)

    print("IP Address\t\tMAC Address\t\t\tDevice Name")
    print("---------------------------------------------------------------")
    for result in results:
        device_name = result["device_name"] if result["device_name"] else "Unknown"
        print(f"{result['ip']}\t\t{result['mac']}\t\t{device_name}")

def main():
    #Testing network scanner
    print("1.Would you like to test all devices connected to your IP\n2.All devices connected to your router\n3.A custom port\n")
    menu_choice = int(input("\nEnter your choice: "))
    if(menu_choice == 1):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        user_socket = s.getsockname()[0]
        user_socket = user_socket + "/24"
        print("user ip address ranges: {}".format(user_socket))
        s.close()
        scan(user_socket)

    elif menu_choice == 2:
        wmi_obj = wmi.WMI()
        wmi_sql = "select IPAddress,DefaultIPGateway from Win32_NetworkAdapterConfiguration where IPEnabled=TRUE"
        wmi_out = wmi_obj.query(wmi_sql)

        for dev in wmi_out:
            web_socket = dev.DefaultIPGateway[0]

        web_socket = web_socket + "/24"
        print("router ip address ranges: {}".format(web_socket))
        scan(web_socket)


    elif menu_choice == 3:
        ip_range = input("Enter IP range: ")
        scan_results = scan(ip_range)

    else:
        print("Invalid input, please try again")
        exit()


if __name__ == "__main__":
    main()
