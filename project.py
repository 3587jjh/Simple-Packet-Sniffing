import pcapy
import socket
from struct import *

# 패킷 번호 pnum, src/dst의 ip/port, http/dns의 data의 정보를 출력한다
def print_infor(pnum, srcip, dstip, srcport, dstport, data):
	# src와 dst의 ip와 port정보 출력
	print(str(pnum)+' '+str(srcip)+':'+str(srcport)+' '+str(dstip)+':'+str(dstport), end=' ')
	if srcport==80 or dstport==80: # http
		print("HTTP " + "Request" if dstport==80 else "Response")
		# http header 정보 출력
		data = str(data)
		endpos = data.find("\\r\\n\\r\\n")
		# 예외: data정보가 없는 경우
		if endpos == -1:
			print("No information")
			return
		lines = data[2:endpos].split("\\r\\n")
		for line in lines:
			print(line)

	else: # dns
		header = unpack("!HHHHHH", data[:12])
		print("DNS ID : " + str(hex(header[0]))[2:])
		# header[1]: 16자리 이진수로 표현한 뒤 각 field의 크기대로 자른다
		line = str(bin(header[1]))[2:]
		line = "0"*(16-len(line))+line
		fsizes = [1, 4, 1, 1, 1, 1, 3, 4]
		offset = 0
		for i in range(0, 8):
			print(line[offset:offset+fsizes[i]], end='')
			if i < 7:
				 print(" | ", end='')
			offset += fsizes[i]
		print()
		# 나머지 header정보를 출력한다
		print("QDCOUNT:" + str(hex(header[2]))[2:])
		print("ANCOUNT:" + str(hex(header[3]))[2:])
		print("NSCOUNT:" + str(hex(header[4]))[2:])
		print("ARCOUNT:" + str(hex(header[5]))[2:])


# 패킷 번호 pnum과 packet data가 주어졌을 때 패킷의 정보를 출력한다
# pcapy의 filter에 의해, 주어진 packet은 http 또는 dns를 사용함이 보장된다
def decode_packet(packet, pnum):
	# offset: 다음에 읽어들일 packet data상의 위치 (byte단위)
	offset = 14 # ethernet header정보를 읽은 뒤의 위치
	header3 = unpack("!BBHHHBBH4s4s", packet[offset:offset+20])
	protocol3 = header3[6]
	srcip = socket.inet_ntoa(header3[8])
	dstip = socket.inet_ntoa(header3[9])
	# offset을 그 다음 payload로 조정
	offset += (header3[0]&15)*4

	if protocol3 == 6: # tcp protocol
		header4 = unpack("!HHLLBBHHH", packet[offset:offset+20])
		srcport = header4[0]
		dstport = header4[1]
		# offset을 그 다음 payload로 조정
		offset += (header4[4]>>4)*4
		data = packet[offset:]
		print_infor(pnum, srcip, dstip, srcport, dstport, data)

	else: # udp protocol
		header4 = unpack("!HHHH", packet[offset:offset+8])
		srcport = header4[0]
		dstport = header4[1]
		# offset을 그 다음 payload로 조정
		offset += 8
		data = packet[offset:]
		print_infor(pnum, srcip, dstip, srcport, dstport, data)

	
# 1. 유저 입력 받기
devs = pcapy.findalldevs() # 시스템상의 네트워크 장비들 불러오기
numDev = len(devs)

# 장비 선택 옵션 나열 후 입력받기
for i in range(0, numDev):
	print(str(i+1)+". "+devs[i])
devID = int(input("Enter the device number (1-"+str(numDev)+"): "))

# sniff할 타입 입력받기
sniffID = int(input("which header do you want to sniff?\
 Enter the number (HTTP=1, DNS=2): "))
sniff = "HTTP" if sniffID==1 else "DNS"

# 2. 패킷 캡쳐 descriptor 열기
snapLen = 2048
promisc = False
timeout = 100
cap = pcapy.open_live(devs[devID-1], snapLen, promisc, timeout)
cap.setfilter('tcp or udp')
if sniff == "HTTP":
	cap.setfilter('src port 80 or dst port 80')
else:
	cap.setfilter('src port 53 or dst port 53')

# 3. 패킷 읽기
pnum = 1
while True:
	print()
	packet = cap.next()[1]
	decode_packet(packet, pnum)
	pnum += 1

