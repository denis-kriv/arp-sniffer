from scapy.all import *
from mac_vendor_lookup import MacLookup
from getmac import get_mac_address


MAC = get_mac_address()


def process_packet(output_format, p):
    src_mac = p[0][0].src
    src_vendor = MacLookup().lookup(src_mac)

    dst_mac = p[0][0].dst
    dst_vendor = MacLookup().lookup(dst_mac)

    if src_mac == MAC:
        packet_type = "request"
    else:
        packet_type = "reply"

    print(output_format.format(packet_type, src_mac, src_vendor, dst_mac, dst_vendor))


def main():
    type_format = "{:<15}"
    mac_format = "{:<30}"
    vendor_format = "{:<30}"
    output_format = f"{type_format} {mac_format} {vendor_format} {mac_format} {vendor_format}"

    print(output_format.format("Packet type", "Source MAC", "MAC Vendor", "Destination MAC", "MAC Vendor"))

    while True:
        try:
            sniff(filter="arp", prn=lambda p: process_packet(output_format, p), count=10)
        except Exception:
            print("Something went wrong.")

        inp = input("Do you want to continue? (y/n) \n")
        while inp != "y" and inp != "n":
            inp = input("Do you want to continue? (y/n) \n")

        if inp == "n":
            break


if __name__ == '__main__':
    main()
