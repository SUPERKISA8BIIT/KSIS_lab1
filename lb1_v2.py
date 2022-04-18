#!/usr/bin/python3

from struct import pack
import time
from uuid import getnode as get_mac
import netifaces as ni
import socket
import asyncio
from sys import argv


timestamps = {}
LOCAL_MAC = [int(("%x" % get_mac())[i:i+2], 16) for i in range(0, 12, 2)]
INTERFACE = "wlp2s0" #интерфейс через который с интернетом общение
ROUTE_MAC = "b4:0f:3b:4e:26:80"


def init_socket():
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    sock.bind((INTERFACE, 0))
    sock.settimeout(3)
    return sock

def add_to_timestamps(packet: bytes):#ключ это набор байт, значение -- юникс время
    timestamps[packet[38:42]] = time.time()


def checkSum(pack: list):          
    checksum = 0
    for i in pack:
        checksum += int.from_bytes(i,"big");
    
    for _ in (1,2):
        dop_code = checksum >> 16
        checksum &= 0xff_ff #cut to chto after 2 bytes, 
        checksum += dop_code
    checksum ^= 0xff_ff #инверсируем
    return checksum

def buildPack(target: str, ttl: int, id: int) -> list: #  сборка пакета
    data = createIcmpPackage(id, ttl)
    data = addIpHeader(data, target, ttl)
    data = addMacLayer(data)
    return data

def createIcmpPackage(id: int, number: int) -> list:  #
    core = [
        pack('!H',0x0800),#!Н переводит число в 4 байты 0x0800 is echo request with 00 code
        pack('!H',0x0000), #checksum
        pack('!H',id), #id
        pack('!H',number), #nomer v pos-ti
    ]

    core[1]=pack('!H', checkSum(core)) 
    return core

def addIpHeader(frame: list, target_ip: str, ttl) -> list:
    tmp = b"".join(frame)#объединяем все элты масства в одну байт-строку
    length = len(tmp)+20#длина icmp+ipv4

    target_ip = target_ip.split(".")
    target_ip = list(map(lambda x: int(x),target_ip))#перевод массива строк в цифры

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

def addMacLayer(frame: list) -> list:   #канальный уровень +
    dest_mac = ROUTE_MAC.split(":")
    dest_mac = list(map(lambda x: int(x, 16),dest_mac))#перевод в цифры

    mac_header = [
        pack('!6B', *dest_mac), 
        pack('!6B', *LOCAL_MAC), 
        pack('!H', 0x0800),
    ]
    return mac_header+frame

def processPack(package: bytes, produced_packs: list):
    if package[12:14]==b"\x08\x00" and package[:6]==pack('!6B', *LOCAL_MAC) and package[23]==0x01:
        ip_addr = package[26:30]
        ip_str = []
        for i in ip_addr:
            ip_str.append(str(i))
        ip_str = ".".join(ip_str)

        if package[34:36]==b'\x0b\x00':
            dt = time.time() - timestamps[package[66:70]]
            produced_packs.append((False, ip_str, int(dt*1000)))
            return produced_packs
        elif package[34:36]==b'\x00\x00':
            dt = time.time() - timestamps[package[38:42]]
            produced_packs.append((True, ip_str, int(dt*1000)))
            return produced_packs
        else:
            return produced_packs
    else:
        return produced_packs

async def recive_pack(number: int):
    packs = []
    start_time = time.time()
    while(time.time()-start_time<10):
        try:
            data = sock.recv(4096)
            packs = processPack(data, packs)      
            if(len(packs))>2:
                break
        except socket.error:
            pass

    if(len(packs)==0):
        print("-- addres unreached --")
        return None    

    print(f"{number:2}: {packs[0][1]:15} | {packs[0][2]:3}ms {packs[1][2]:3}ms {packs[2][2]:3}ms |")
    return packs[0][0]       

if(len(argv)<2):
    target = input("Enter address: ")
else:
    target = argv[1]

sock = init_socket()

async def main():
    ttl = 1
    is_reached = False
    while(not is_reached):
        task = asyncio.create_task(recive_pack(ttl))

        data1 = b''.join(buildPack(target, ttl, 256))
        sock.send(data1)#объединение сформированного пакета в байт строку и его отправка
        add_to_timestamps(data1)

        data2 = b''.join(buildPack(target, ttl, 282)) 
        sock.send(data2)#о
        add_to_timestamps(data2)

        data3 = b''.join(buildPack(target, ttl, 333))
        sock.send(data3)#о
        add_to_timestamps(data3)

        ttl += 1
        is_reached = await task
        if is_reached == None:
            break

asyncio.run(main())
sock.close()
