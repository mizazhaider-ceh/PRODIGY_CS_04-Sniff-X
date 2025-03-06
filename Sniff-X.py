"""
Task 4 - Prodigy Infotech

Sniff~X - Network Packet Analyzer

Developed as part of my internship at Prodigy Infotech, Sniff~X is an ethical network packet analyzer designed for authorized security testing and research purposes.
It captures and analyzes network traffic in real time, helping to understand data flow, identify potential vulnerabilities, and enhance network security.

This project deepened my knowledge of packet sniffing, network protocols, and the Scapy library in Python.
It also reinforced my understanding of cybersecurity best practices and responsible network monitoring.

⚠ Disclaimer: This tool is strictly for educational and ethical use only. Unauthorized use is illegal and unethical.
"""


from scapy.all import sniff
import time
import os

#========================================================================
# Defining Colors to use in this internship project
RED = "\033[91m"
GREEN = "\033[32m"
BLUE = "\033[94m"
PURPLE = "\033[95m"
GOLD = "\033[38;5;220m"
CYAN = "\033[36m"
RESET = "\033[0m"  # Reset color
#========================================================================

banner = f""" {GREEN}
        ███████╗███╗   ██╗██╗███████╗███████╗██╗  ██╗
        ██╔════╝████╗  ██║██║██╔════╝██╔════╝╚██╗██╔╝
        ███████╗██╔██╗ ██║██║█████╗  █████╗   ╚███╔╝ 
        ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝   ██╔██╗ 
        ███████║██║ ╚████║██║██║     ██║     ██╔╝ ██╗
        ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚═╝  ╚═╝
{RESET}
\033[35m~~~~~  Developed by Aspiring Pentester Mr. Izaz   ~~~~~ \033[0m 
\033[38;5;220m~~~~~  Follow Here: GitHub.com/mizazhaider-ceh  ~~~~~\033[0m
\033[94m~~~~~ Internship Task/Project Assigned by ProDigy Infotech ~~~~~\033[0m
"""
print(banner)

#============= Introduction =================

print("\033[32m=" * 65 ,"\033[0m")
print(f"~ {PURPLE}   Welcome to SniffX - The Ultimate Packet Analyzer\033[0m")
print(f"~ {GOLD}  Capture, Analyze & Decode Network Traffic Efficiently\033[0m")
print(f"~{CYAN}  Use Responsibly! Unauthorized Use is Strictly Prohibited.\033[0m")
print("\033[32m=" * 65 ,"\033[0m") 

#=============================================================

user_choice = input(f"\n~{GOLD} Do you want to start --> Catpturing Packets (yes,y/No,n):{RESET} ")
if user_choice not in ["yes", "y"]:
    print("\033[31mPermission denied. Exiting program...\033[0m")
    exit()
    
#=============================================================    
while True:
    try:
        count_value = int(input("\n~\033[94m Enter the number of packets to capture (0 for infinite): \033[0m"))
        if count_value < 0:
            print("\033[91mInvalid input! Please enter 0 or a positive number.\033[0m")
        else:
            break
    except ValueError:
        print("\033[91mInvalid input! Please enter a valid number.\033[0m")

#=============================================================

print(f"~~~~{GOLD} Its Going to start capturing......{RESET}")
time.sleep(1)

#=====================================

captured_packets=[]
protocols = { 1: "ICMP", 6: "TCP", 17: "UDP" } #{1: "ICMP", 6: "TCP", 17: "UDP"}
os.makedirs("Files", exist_ok=True)

#======================================================
def packet_analyze(packet):
    if packet.haslayer('IP'):
        #=======================
        source_ip = packet['IP'].src
        desti_ip = packet['IP'].dst
        protocol = protocols.get(packet.proto , "other")
        payload = bytes(packet.payload).hex()[:40]

        #=======================
        
        packet_info_live = f"""
        {GOLD}============ Captured ============={RESET}
        {BLUE}Source IP: {RESET} {GREEN}{source_ip}{RESET}
        {BLUE}Destination IP: {RESET}{RED}{desti_ip}{RESET}
        {BLUE}Protocol: {RESET} {GOLD}{protocol}{RESET}
        {BLUE}Payload: {RESET} {PURPLE}{payload}{RESET}
        {GOLD}============          ============={RESET}
        """
        #=========================================      
          
        packet_information_file = f""" 
        ============ Captured =============
        Source IP : {source_ip}
        Destination IP : {desti_ip}
        Protocol : {protocol}
        Payload : {payload}
        ============          =============
        """
        #=========================================   
        
        captured_packets.append(packet_information_file)
        print(packet_info_live)
        
#==================================================      
if count_value == 0:
    sniff(prn=packet_analyze, store=False)  # Capture packets indefinitely
else:
    sniff(prn=packet_analyze, count=count_value)  # Capture a limited number

#========================

print(f"~~~~{CYAN} Do you want to save (Yes,y/No,n)\033[0m")
choice = input(f"~~~{GOLD} Enter your choice\033[0m : ")
if choice == "yes" or choice == "y" :
    with open("Files/Packets.txt","a") as file:
        file.writelines(packet + "\n" for packet in captured_packets)
        print(f"~ {PURPLE}File is successfully saved under Files folder as Packets.txt")
else:
    print(f"{RED}\n~ Ok as you wish....Exiting....{RESET}")
    exit()
    
        