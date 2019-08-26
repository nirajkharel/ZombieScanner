#! python3
# platform = Ubuntu
# stealthScan.py - Scan the ports anonymously.

# Before running the program - need to off the firewall of zombie pc at least.

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # it supresses the messages that have lower level of seriousness
import sys
import socket
import time
from scapy.all import *

# For decoration on the shell
# Includes colors, fonts, sizes
BLUE, RED, WHITE, YELLOW, GREEN, END = '\33[94m', '\033[91m', '\33[97m', '\33[93m', '\033[32m', '\033[0m'


sys.stdout.write(RED + """    

	  ██████  ▄████▄   ▄▄▄       ███▄    █     ███▄ ▄███▓▓█████ 
	▒██    ▒ ▒██▀ ▀█  ▒████▄     ██ ▀█   █    ▓██▒▀█▀ ██▒▓█   ▀ 
	░ ▓██▄   ▒▓█    ▄ ▒██  ▀█▄  ▓██  ▀█ ██▒   ▓██    ▓██░▒███   
	  ▒   ██▒▒▓▓▄ ▄██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒   ▒██    ▒██ ▒▓█  ▄ 
	▒██████▒▒▒ ▓███▀ ░ ▓█   ▓██▒▒██░   ▓██░   ▒██▒   ░██▒░▒████▒
	▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒    ░ ▒░   ░  ░░░ ▒░ ░
	░ ░▒  ░ ░  ░  ▒     ▒   ▒▒ ░░ ░░   ░ ▒░   ░  ░      ░ ░ ░  ░
	░  ░  ░  ░          ░   ▒      ░   ░ ░    ░      ░      ░   
	      ░  ░ ░            ░  ░         ░           ░      ░  ░
	         ░                                                  
			                                                                                                                                 
"""  + END + BLUE +
'\n' + 'Zombie Scanner'.format(RED, END).center(69) +
'\n' + 'Developed by: {}NUMB | NIRAJ'.format(YELLOW, RED, YELLOW, BLUE, END).center(76)+ '\n\n')

# essential needed for scanning ports.
zombie_ip = input(' ' * 10 + 'Enter Zombie IP: ')
victim_ip = input('\n'+' ' * 10 + 'Enter victim IP: ')
try:
	start_port = int(input('\n'+' ' * 10 + 'Port start from: '))
# if left empty, set to 1
except:
	start_port = 1
	sys.stdout.write(RED + 'Set to default value: 1' + END + YELLOW)
try:
	end_port = int(input('\n'+' ' * 10 + 'Port end from: '))
# if left empty, set to 100
except:
	end_port = 100
	sys.stdout.write(RED + 'Set to default value: 100' + END)	

# option for detecting OS of the victim host
os_detection = input('\n'+' '*10+'OS Detection(Y/N): ')


def scan_now(start_port, end_port, victim_ip, zombie_ip,os_detection):
	if start_port < end_port:
		sys.stdout.write(GREEN + '\n\n'+' ' * 10 + 'PORT NO.      SERVICES' + '\n' + END)

		start_time = time.time()
		for port in range(start_port, end_port):
			try:

				# send SYN/ACK packet to zombie from attacker
				attack_zombie = sr1(IP(dst=zombie_ip)/TCP(dport=port,flags='SA'),timeout=2,verbose=0)

				# send SYN packet to victim from attacker
				attack_victim = sr1(IP(dst=victim_ip, src= zombie_ip)/TCP(dport=port,flags='S'),timeout=2,verbose=0)

				# send SYN/ACK packet to zombie from attacker again
				attack_zombie_again = sr1(IP(dst=zombie_ip)/TCP(dport=port,flags='SA'),timeout=2,verbose=0)				

				# if ipid value after all operation is increased by 2, then port is open
				if attack_zombie_again[IP].id == (attack_zombie[IP].id + 2):
					print(' ' * 10 + str(port) + ' /tcp' + '        ' + socket.getservbyport(port))

			except:
				pass
		# The time to leave ttl value of linux is less than 64 and window is more than 64.
		os_detection_response = sr1(IP(dst=victim_ip, src= zombie_ip)/TCP(dport=80,flags='S'),timeout=2,verbose=0)
		if os_detection.lower() == 'y':
			if os_detection_response[IP].ttl <= 64:
				print(' '*10 + 'Operating System : Linux/Unix')
			else:
				print(' '*10 + 'Operating System : Microsoft Windows')
		end_time = time.time()
		time_taken = round((end_time-start_time),2)
		print(' ' * 10 + 'Finished in {} seconds.'.format(time_taken))
	else:
		print(' '*10 + 'Invalid range of port.  Exiting....')
		sys.exit()

if __name__ == '__main__':
	scan_now(start_port, end_port, victim_ip, zombie_ip,os_detection)
		
