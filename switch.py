#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

mac_table = {}
vlan_table = {}
interface_status = {}

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

def create_bpdu(src_mac, root_bridge_ID, root_path_cost, switch_bridge_ID):
    format = "!6s6sIII"
    dest_mac = b"\x01\x80\xC2\x00\x00\x00"

    return struct.pack(format, dest_mac, src_mac, root_bridge_ID, root_path_cost, switch_bridge_ID)

def send_bdpu_every_sec(vlan_table):
    global is_root_bridge, root_bridge_ID, root_path_cost, root_port, mac_table, interface_status, switch_bridge_ID, interfaces
    while True:
        # TODO Send BDPU every second if necessary
        if is_root_bridge:
            bpdu = create_bpdu(get_switch_mac(), root_bridge_ID, root_path_cost, switch_bridge_ID)
            for i in interfaces:
                i_name = get_interface_name(i)
                i_type = get_interface_vlan(i_name, vlan_table)

                if i_type == "trunk":
                    send_to_link(i, len(bpdu), bpdu)
        time.sleep(1)

def process_given_bpdu(interface, bpdu):
    global root_bridge_ID, root_path_cost, switch_bridge_ID, interfaces, root_port, is_root_bridge
    dest_mac, src_mac, root_bridge_ID_bpdu, root_path_cost_bpdu, switch_bridge_ID_bpdu = struct.unpack("!6s6sIII", bpdu)
    # print("Received BPDU from interface {} with root_bridge_ID = {}, root_path_cost = {}, switch_bridge_ID = {}".format(get_interface_name(interface), root_bridge_ID_bpdu, root_path_cost_bpdu, switch_bridge_ID_bpdu))

    if root_bridge_ID_bpdu < root_bridge_ID:
        root_bridge_ID = root_bridge_ID_bpdu
        root_path_cost = root_path_cost_bpdu + 10
        root_port = interface
        # print("New root bridge: {}, root path cost: {}, root port: {}".format(root_bridge_ID, root_path_cost, get_interface_name(root_port)))

        if is_root_bridge:
            for i in interfaces:
                interface_name = get_interface_name(i)
                interface_type = get_interface_vlan(interface_name, vlan_table)
                if i != root_port and interface_type != "access":
                    interface_status[get_interface_name(i)] = "blocking"

            is_root_bridge = False
        
        if interface_status[get_interface_name(root_port)] == "blocking":
            interface_status[get_interface_name(root_port)] = "listening"
        
        bpdu = create_bpdu(get_switch_mac(), root_bridge_ID, root_path_cost, switch_bridge_ID)
        # print("Sending BPDU to all interfaces")
        # print("Root bridge ID este: ", root_bridge_ID)
        # print("Root path cost este: ", root_path_cost)
        # print("Switch bridge ID este: ", switch_bridge_ID)
    
        for i in interfaces:
            interface_name = get_interface_name(i)
            interface_type = get_interface_vlan(interface_name, vlan_table)

            if interface_type == "trunk":
                send_to_link(i, len(bpdu), bpdu)

    elif root_bridge_ID_bpdu == root_bridge_ID:
        # print("Root bridge ID is the same")
        if interface == root_port and root_path_cost_bpdu + 10 < root_path_cost:
            root_path_cost = root_path_cost_bpdu + 10

        elif interface != root_port:
            if root_path_cost_bpdu > root_path_cost:
                if interface_status[get_interface_name(interface)] != "listening":
                    interface_status[get_interface_name(interface)] = "listening"

    elif switch_bridge_ID_bpdu == switch_bridge_ID:
        interface_status[get_interface_name(interface)] = "blocking"

    if switch_bridge_ID_bpdu == root_bridge_ID:
        for i in interfaces:
            interface_status[get_interface_name(i)] = "listening"

def is_unicast_mac(mac):
    return mac[0] & 1 == 0

def get_interface_vlan(interface, vlan_table):
    if vlan_table.get(interface) == 'T':
        return "trunk"
    return "access"

def forward_frame(interfaceDest, data, length, vlan_id, vlan_table, source_interface_type, dest_mac):
    interface_type = get_interface_vlan(get_interface_name(interfaceDest), vlan_table)
    interfaceDest_name = get_interface_name(interfaceDest)

    # print("Forwarding frame to interface {} ({})".format(interfaceDest, interface_type))

    vlan_entry = vlan_table.get(interfaceDest_name)
    # print("Vlan entry este: ", vlan_entry)

    in_vlan = (vlan_table.get(interfaceDest_name) == vlan_id) or vlan_table.get(interfaceDest_name) == 'T'
    if not in_vlan:
        # print("Dropping frame because of VLAN mismatch ({} != {})".format(vlan_id, vlan_table.get(interfaceDest_name)))
        return
    if interface_status[interfaceDest_name] == "blocking":
        # print("Dropping frame because interface is blocking")
        return

    # print("interface type {} and interfaceDest_name {}".format(interface_type, interfaceDest_name))
    # # Adaugă tag-ul VLAN pe trunk, dacă este necesar
    if interface_type == "access" and source_interface_type == "trunk" and dest_mac != "01:80:c2:00:00:00":
        data, length = remove_vlan_tag(data, length)
    if interface_type == "trunk" and source_interface_type == "access":
        data, length = add_vlan_tag(data, vlan_id, length)

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
        if vlan_id != 'T':
            vlans[port_name] = int(vlan_id)
        else:
            vlans[port_name] = vlan_id
    return switch_priority, vlans
interfaces = {}
is_root_bridge = True # is root bridge

switch_bridge_ID = None # current switch bridge ID
root_bridge_ID = None # root bridge ID
root_path_cost = None # cost to root bridge
root_port = None # port to root bridge

def main():
    global switch_bridge_ID, root_bridge_ID, root_path_cost, root_port, interfaces
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    switch_priority, vlan_table = get_configured_vlans(switch_id)

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    switch_bridge_ID = switch_priority
    root_bridge_ID = switch_bridge_ID
    root_path_cost = 0

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec, args=(vlan_table,))
    t.start()

    # Printing interface names
    for i in interfaces:
        interface_name = get_interface_name(i)
        interface_type = get_interface_vlan(interface_name, vlan_table)

        if interface_type == "trunk":
            interface_status[interface_name] = "blocking"
        elif interface_type == "access":
            interface_status[interface_name] = "listening"

    helloBpdu = struct.pack("!6s6sIII", b"\x01\x80\xC2\x00\x00\x00", get_switch_mac(), switch_priority, 0, switch_priority)
    for i in interfaces:
        send_to_link(i, len(helloBpdu), helloBpdu) # send hello bpdu on all interfaces to detect root bridge

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

        # print(f'Destination MAC: {dest_mac}')
        # print(f'Source MAC: {src_mac}')
        # print(f'EtherType: {ethertype}')

        # print("Received frame of size {} on interface {}".format(length, get_interface_name(interface)), flush=True)

        interface_type = get_interface_vlan(get_interface_name(interface), vlan_table)

        if vlan_id == -1 and interface_type == "access":
            vlan_id = vlan_table[get_interface_name(interface)] # packet came from a host -> asociates a vlan_id
            # print(f"Vlan id este: {vlan_id}")

        # TODO: Implement forwarding with learning
        # TODO: Implement VLAN support
        # TODO: Implement STP support

        mac_table[src_mac] = interface
        dest_mac_bytes = bytes.fromhex(dest_mac.replace(":", ""))
        is_unicast = is_unicast_mac(dest_mac_bytes)
        
        if is_unicast:
            if dest_mac in mac_table:
                forward_frame(mac_table[dest_mac], data, length, vlan_id, vlan_table, interface_type, dest_mac)
            else:
                for o in interfaces:
                    if o != interface:
                        forward_frame(o, data, length, vlan_id, vlan_table, interface_type, dest_mac)
        else:
            if dest_mac == "01:80:c2:00:00:00":
                # print("Received BPDU")
                process_given_bpdu(interface, data)
                continue
            for o in interfaces:
                if o != interface:
                    forward_frame(o, data, length, vlan_id, vlan_table, interface_type, dest_mac)
        

        # data is of type bytes.
        # send_to_link(i, length, data)

if __name__ == "__main__":
    main()
