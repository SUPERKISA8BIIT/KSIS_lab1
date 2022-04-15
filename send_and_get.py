  #!/usr/bin/python3

from struct import pack
from typing import List
from uuid import getnode as get_mac
import netifaces as ni
import socket

LOCAL_MAC = [int(("%x" % get_mac())[i:i+2], 16) for i in range(0, 12, 2)]
LOCAL_MAC = [41, 53, 44,108,229,118]

INTERFACE = "wlp2s0"
ROUTE_MAC = "b4:0f:3b:4e:26:80"
cache = []

def checkSum(pack: list) -> int:
    checksum = 0
    for i in pack:
        checksum += int.from_bytes(i,"big");
    
    for _ in (1,2):
        dop_code = checksum >> 16
        checksum &= 0xff_ff
        checksum += dop_code
    checksum ^= 0xff_ff #logic not
    return checksum

def buildPack(target: str, ttl: int) -> list:
    data = createIcmpPackage()
    data = addIpHeader(data, target, ttl)
    data = addMacLayer(data)
    return data


def addMacLayer(frame: list) -> list:   
    dest_mac = ROUTE_MAC.split(":")
    dest_mac = list(map(lambda x: int(x, 16),dest_mac))
    mac_header = [
        pack('!6B', *dest_mac), 
        pack('!6B', *LOCAL_MAC), 
        pack('!H', 0x0800),
    ]
    return mac_header+frame

def addIpHeader(frame: list, target_ip: str, ttl) -> list:
    tmp = b"".join(frame)
    length = len(tmp)+20

    target_ip = target_ip.split(".")
    target_ip = list(map(lambda x: int(x),target_ip))

    local_ip = [int(x) for x in ni.ifaddresses(INTERFACE)[ni.AF_INET][0]['addr'].split('.')]

    ip_header = [
        pack('!H', 0x4500),
        pack('!H', length),
        pack('!H', 0x3e81), #id
        pack('!H', 0x4000),
        pack('!2B', ttl, 0x01), #ttl + #icmp protocole
        pack('!H', 0), #checksum
        pack('!2B', *(local_ip[:2])),
        pack('!2B', *(local_ip[2:])),
        pack('!2B', *(target_ip[:2])),
        pack('!2B', *(target_ip[2:])),
    ]

    checksum = checkSum(ip_header)
    ip_header[5]=pack('!H', checksum)

    return ip_header+frame

def processPack(package: bytes, ttl: int):
    if package[12:14]==b"\x08\x00" and package[:6]==pack('!6B', *LOCAL_MAC):
        print("ok")
        ip_addr = package[26:30]
        ip_str = []
        for i in ip_addr:
            ip_str.append(str(i))
        ip_str = ".".join(ip_str)

        if package[34:36]==b'\x0b\x00':
            if ip_str not in cache:
                print(ip_str)
                cache.append(ip_str)
            return False, ttl+1
        elif package[34:36]==b'\x00\x00':
            return True, ttl+1
        else:
            return False, ttl
    else:
        print(package[:6], package[7:12], pack('!6B', *LOCAL_MAC), LOCAL_MAC)
        return False, ttl


def createIcmpPackage() -> list:
    core = [
        pack('!H',0x0800),
        pack('!H',0x0000), #checksum
        pack('!H',0x1101), #id
        pack('!H',0x0001),
    ]

    core[1]=pack('!H', checkSum(core))
    return core


def sendPack(pack: list, ttl: int):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind((INTERFACE, 0))

    sock.send(b''.join(pack))
    data = sock.recv(70)
    sock.close()
    return processPack(data, ttl)


target = input("Enter address: ")
#target = "8.8.8.8"

ttl = 1
while(True):
    data = buildPack(target, ttl)
    is_reached, ttl = sendPack(data, ttl)
    if is_reached:
        break

print("end")
