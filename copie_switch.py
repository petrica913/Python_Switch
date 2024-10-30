#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def add_vlan_tag(data, vlan_id, length):
    return data[0:12] + create_vlan_tag(vlan_id) + data[12:], length + 4

def remove_vlan_tag(data, length):
    return data[0 :12] + data[16:], length - 4

def send_bdpu_every_sec():
    while True:
        # TODO Send BDPU every second if necessary
        time.sleep(1)
def is_unicast_mac(mac):
    return mac[0] & 1 == 0

mac_table = {}
vlan_table = {}

def get_interface_vlan(interface, vlan_table):
    if vlan_table.get(interface) == 'T':
        return "trunk"
    return "access"

def forward_frame(interfaceDest, data, length, vlan_id):
    interface_type = get_interface_vlan(get_interface_name(interfaceDest), vlan_table)
    interfaceDest_name = get_interface_name(interfaceDest)

    print("Forwarding frame to interface {} ({})".format(interfaceDest, type))
    # if interfaceDest_name in vlan_table:
    #     if vlan_id != vlan_table[interfaceDest_name] and interface_type == "access":
    #         print("Dropping frame because of VLAN mismatch")
    #         return


    
    # if interface_type == "trunk":
    #     data, length = add_vlan_tag(data, vlan_id, length)
    send_to_link(interfaceDest, length, data)

def get_configured_vlans(switch_id):
    fin = open("./configs/switch{}.cfg".format(switch_id))
    lines = fin.readlines()
    switch_priority = int(lines[0].strip())
    vlans = {}
    for line in lines[1:]:
        parts = line.split()
        port_name = parts[0]
        vlan_id = parts[1]
        if vlan_id == 'T':
            vlans[port_name] = "T"
        else:
            vlans[port_name] = int(vlan_id)
    return switch_priority, vlans

def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    switch_priority, vlan_table = get_configured_vlans(switch_id)

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()

    # Printing interface names
    for i in interfaces:
        print(get_interface_name(i))

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

        print(f'Destination MAC: {dest_mac}')
        print(f'Source MAC: {src_mac}')
        print(f'EtherType: {ethertype}')

        print("Received frame of size {} on interface {}".format(length, interface), flush=True)

        interface_type = get_interface_vlan(get_interface_name(interface), vlan_table)

        if vlan_id != -1 and interface_type == "access":
            vlan_id = vlan_table[get_interface_name(interface)] # packet came from a host -> asociates a vlan_id
        elif interface_type == "trunk":
            data, length = remove_vlan_tag(data, length) # packet came from a trunk -> removes vlan tag

        # TODO: Implement forwarding with learning
        mac_table[src_mac] = interface
        dest_mac_bytes = bytes.fromhex(dest_mac.replace(":", ""))
        is_unicast = is_unicast_mac(dest_mac_bytes)

        if is_unicast:
            if dest_mac in mac_table:
                forward_frame(mac_table[dest_mac], data, length, vlan_id)
            else:
                for o in interfaces:
                    if o != interface:
                        forward_frame(o, data, length, vlan_id)
        else:
            for o in interfaces:
                if o != interface:
                    forward_frame(o, data, length, vlan_id)
        # TODO: Implement VLAN support
        
        # TODO: Implement STP support

        # data is of type bytes.
        # send_to_link(i, length, data)

if __name__ == "__main__":
    main()
