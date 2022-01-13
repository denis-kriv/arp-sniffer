import socket
import binascii
import struct
import os
import re
import time
from getpass import getuser
from urllib.request import urlopen

OUI_STORE = os.path.join(os.path.expanduser("~" + getuser()), ".oui-cache")
CACHE_TIME = 604800
IEEE_URL = "http://standards-oui.ieee.org/oui/oui.txt"
BUFFER_SIZE = 65535


def get_vendor(mac):
    if time.time() - os.stat(OUI_STORE).st_ctime > CACHE_TIME:
        with open(OUI_STORE, "wb") as oui:
            for line in urlopen(IEEE_URL).readlines():
                oui.write(line)

    formatted_mac = "-".join(mac.decode("ascii").split("-")[:3])
    with open(OUI_STORE, "r", encoding="utf-8") as oui:
        for line in iter(oui):
            if re.search(formatted_mac, line, re.IGNORECASE):
                return line.split("\t")[2].rstrip()


def sniff(sniff_socket, output_format):
    raw_data, _ = sniff_socket.recvfrom(BUFFER_SIZE)
    _, _, ptype = struct.unpack("!6s6sH", raw_data[:14])

    if socket.htons(ptype) == 1544:
        _, _, _, _, opcode, src_mac, _, dst_mac, _ = struct.unpack("2s2s1s1s2s6s4s6s4s", raw_data[14:42])

        opcode = binascii.hexlify(opcode, "-")
        src_mac = binascii.hexlify(src_mac, "-")
        dst_mac = binascii.hexlify(dst_mac, "-")

        print(output_format.format("request" if opcode == bytes("00-01", encoding="utf-8") else "reply",
                                   bytes(src_mac).decode(), get_vendor(src_mac),
                                   bytes(src_mac).decode(), get_vendor(dst_mac)))


def main():
    sniff_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))

    output_format = "{:<15} {:<30} {:<30} {:<30} {:<30}"
    print(output_format.format("Packet type", "Source MAC", "MAC Vendor", "Destination MAC", "MAC Vendor"))
    while True:
        sniff(sniff_socket, output_format)


if __name__ == "__main__":
    main()
