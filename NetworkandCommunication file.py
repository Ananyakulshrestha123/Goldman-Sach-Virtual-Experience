#!/usr/bin/env python
# coding: utf-8

# In[1]:


import dpkt
import socket

def connection_id_to_str(cid, v=4):
    """This converts the connection ID cid which is a tuple of (source_ip_address, source_tcp_port, destination_ip_address,
    destination_tcp_port) to a string. v is either 4 for IPv4 or 6 for IPv6"""
    if v == 4:
        src_ip_addr_str = socket.inet_ntoa(cid[0])
        dst_ip_addr_str = socket.inet_ntoa(cid[2])
        return src_ip_addr_str + ":" + str(cid[1]) + "<=>" + dst_ip_addr_str + ":" + str(cid[3])
    elif v == 6:
        src_ip_addr_str = socket.inet_ntop(socket.AF_INET6, cid[0])
        dst_ip_addr_str = socket.inet_ntop(socket.AF_INET6, cid[2])
        return src_ip_addr_str + "." + str(cid[1]) + "<=>" + dst_ip_addr_str + "." + str(cid[3])
    else:
        raise ValueError('Argument to connection_id_to_str must be 4 or 6, is %d' % v)

def analyze_pcap_file(file_path):
    """This function analyzes a pcap file and prints flow information"""
    with open(file_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        print("Flow\tSource IP\tSource Port\tDestination IP\tDestination Port\tTimestamp\tDirection\tData Size (bytes)\tData Size (bits per second)")

        flow_windows = {}  # Dictionary to store flow windows

        for timestamp, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                continue

            ip = eth.data
            if ip.p != dpkt.ip.IP_PROTO_TCP:
                continue

            tcp = ip.data
            connection_id = (ip.src, tcp.sport, ip.dst, tcp.dport)
            reverse_connection_id = (ip.dst, tcp.dport, ip.src, tcp.sport)

            flow = connection_id_to_str(connection_id)
            reverse_flow = connection_id_to_str(reverse_connection_id)

            if flow in flow_windows:
                flow_windows[flow].append((timestamp, buf))
            elif reverse_flow in flow_windows:
                flow_windows[reverse_flow].append((timestamp, buf))
            else:
                flow_windows[flow] = [(timestamp, buf)]

        # Print flows in separate windows
        for flow, packets in flow_windows.items():
            print(f"{flow}")
            total_forward_packets = 0
            total_backward_packets = 0
            total_forward_bytes = 0
            total_backward_bytes = 0
            direction_forward = "A to B"
            direction_backward = "B to A"

            for packet in packets:
                timestamp = packet[0]
                buf = packet[1]
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                tcp = ip.data

                # Calculate packet size in bytes
                packet_size = len(buf)

                # Determine the direction of the packet
                direction = direction_forward if connection_id_to_str((ip.src, tcp.sport, ip.dst, tcp.dport)) == flow else direction_backward

                if direction == direction_forward:
                    total_forward_packets += 1
                    total_forward_bytes += packet_size
                else:
                    total_backward_packets += 1
                    total_backward_bytes += packet_size

                # Calculate bits per second
                total_bytes = total_forward_bytes + total_backward_bytes
                                # Calculate bits per second
                total_bits_per_second = total_bytes * 8 / timestamp

                print(f"\t{direction}\t{timestamp:.2f}\t{packet_size}\t{total_bits_per_second:.2f}")

            print(f"\t{direction_forward}:\n\t\tTotal packets: {total_forward_packets}\n\t\tTotal bytes: {total_forward_bytes}\n")
            print(f"\t{direction_backward}:\n\t\tTotal packets: {total_backward_packets}\n\t\tTotal bytes: {total_backward_bytes}\n")

analyze_pcap_file('E:\PPT Reader\http_ipv4_complex.cap')

               


# In[4]:


import dpkt
import socket

def connection_id_to_str(cid, v=4):
    """This converts the connection ID cid which is a tuple of (source_ip_address, source_tcp_port, destination_ip_address,
    destination_tcp_port) to a string. v is either 4 for IPv4 or 6 for IPv6"""
    if v == 4:
        src_ip_addr_str = socket.inet_ntoa(cid[0])
        dst_ip_addr_str = socket.inet_ntoa(cid[2])
        return src_ip_addr_str + ":" + str(cid[1]) + "<=>" + dst_ip_addr_str + ":" + str(cid[3])
    elif v == 6:
        src_ip_addr_str = socket.inet_ntop(socket.AF_INET6, cid[0])
        dst_ip_addr_str = socket.inet_ntop(socket.AF_INET6, cid[2])
        return src_ip_addr_str + "." + str(cid[1]) + "<=>" + dst_ip_addr_str + "." + str(cid[3])
    else:
        raise ValueError('Argument to connection_id_to_str must be 4 or 6, is %d' % v)

def analyze_pcap_file(file_path):
    """This function analyzes a pcap file and prints flow information"""
    with open(file_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        print("Flow\tSource IP\tSource Port\tDestination IP\tDestination Port\tTotal Packets (A to B)\tTotal Packets (B to A)\tTotal Bytes (A to B)\tTotal Bytes (B to A)\tTotal Bytes")

        flow_windows = {}  # Dictionary to store flow windows

        for _, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                continue

            ip = eth.data
            if ip.p != dpkt.ip.IP_PROTO_TCP:
                continue

            tcp = ip.data
            connection_id = (ip.src, tcp.sport, ip.dst, tcp.dport)
            reverse_connection_id = (ip.dst, tcp.dport, ip.src, tcp.sport)

            flow = connection_id_to_str(connection_id)
            reverse_flow = connection_id_to_str(reverse_connection_id)

            if flow in flow_windows:
                flow_windows[flow].append(buf)
            elif reverse_flow in flow_windows:
                flow_windows[reverse_flow].append(buf)
            else:
                flow_windows[flow] = [buf]

        # Print flows in separate windows
        for flow, packets in flow_windows.items():
            forward_packets = 0
            backward_packets = 0
            forward_bytes = 0
            backward_bytes = 0

            for buf in packets:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                tcp = ip.data
                packet_size = len(buf)

                if connection_id_to_str((ip.src, tcp.sport, ip.dst, tcp.dport)) == flow:
                    forward_packets += 1
                    forward_bytes += packet_size
                else:
                    backward_packets += 1
                    backward_bytes += packet_size

            total_forward_bytes = forward_bytes
            total_backward_bytes = backward_bytes
            total_bytes = total_forward_bytes + total_backward_bytes

            print(f"{flow}\t{len(packets)} packets\t{forward_packets}\t{backward_packets}\t{total_forward_bytes}\t{total_backward_bytes}\t{total_bytes}")

# Usage example
analyze_pcap_file('E:\PPT Reader\http_ipv4_complex.cap')


# In[6]:


import dpkt
import socket

def connection_id_to_str(cid, v=4):
    """This converts the connection ID cid which is a tuple of (source_ip_address, source_tcp_port, destination_ip_address,
    destination_tcp_port) to a string. v is either 4 for IPv4 or 6 for IPv6"""
    if v == 4:
        src_ip_addr_str = socket.inet_ntoa(cid[0])
        dst_ip_addr_str = socket.inet_ntoa(cid[2])
        return src_ip_addr_str + ":" + str(cid[1]) + "<=>" + dst_ip_addr_str + ":" + str(cid[3])
    elif v == 6:
        src_ip_addr_str = socket.inet_ntop(socket.AF_INET6, cid[0])
        dst_ip_addr_str = socket.inet_ntop(socket.AF_INET6, cid[2])
        return src_ip_addr_str + "." + str(cid[1]) + "<=>" + dst_ip_addr_str + "." + str(cid[3])
    else:
        raise ValueError('Argument to connection_id_to_str must be 4 or 6, is %d' % v)

def analyze_pcap_file(file_path):
    """This function analyzes a pcap file and prints flow information"""
    with open(file_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        print("Flow\tSource IP\tSource Port\tDestination IP\tDestination Port\tDirection\tTimestamp (s)\tData Size")

        flow_windows = {}  # Dictionary to store flow windows

        for _, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                continue

            ip = eth.data
            if ip.p != dpkt.ip.IP_PROTO_TCP:
                continue

            tcp = ip.data
            connection_id = (ip.src, tcp.sport, ip.dst, tcp.dport)
            reverse_connection_id = (ip.dst, tcp.dport, ip.src, tcp.sport)

            flow = connection_id_to_str(connection_id)
            reverse_flow = connection_id_to_str(reverse_connection_id)

            if flow in flow_windows:
                flow_windows[flow].append(buf)
            elif reverse_flow in flow_windows:
                flow_windows[reverse_flow].append(buf)
            else:
                flow_windows[flow] = [buf]

        # Print flows in separate windows
        for flow, packets in flow_windows.items():
            forward_packets = 0
            backward_packets = 0

            for i, buf in enumerate(packets):
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                tcp = ip.data
                packet_size = len(buf)
                timestamp = i  # Starting from 0 for the first packet

                if connection_id_to_str((ip.src, tcp.sport, ip.dst, tcp.dport)) == flow:
                    direction = "Forward"
                    forward_packets += 1
                else:
                    direction = "Backward"
                    backward_packets += 1

                print(f"{flow}\t{direction}\t{timestamp}\t{packet_size}")

            total_packets = forward_packets + backward_packets

            print(f"\tTotal packets: {total_packets}\n")

# Usage example
analyze_pcap_file('E:\PPT Reader\http_ipv4_complex.cap')


# In[2]:


import dpkt
import socket

def connection_id_to_str(cid, v=4):
    """This converts the connection ID cid which is a tuple of (source_ip_address, source_tcp_port, destination_ip_address,
    destination_tcp_port) to a string. v is either 4 for IPv4 or 6 for IPv6"""
    if v == 4:
        src_ip_addr_str = socket.inet_ntoa(cid[0])
        dst_ip_addr_str = socket.inet_ntoa(cid[2])
        return src_ip_addr_str + ":" + str(cid[1]) + "<=>" + dst_ip_addr_str + ":" + str(cid[3])
    elif v == 6:
        src_ip_addr_str = socket.inet_ntop(socket.AF_INET6, cid[0])
        dst_ip_addr_str = socket.inet_ntop(socket.AF_INET6, cid[2])
        return src_ip_addr_str + "." + str(cid[1]) + "<=>" + dst_ip_addr_str + "." + str(cid[3])
    else:
        raise ValueError('Argument to connection_id_to_str must be 4 or 6, is %d' % v)

def analyze_pcap_file(file_path):
    """This function analyzes a pcap file and prints flow information"""
    with open(file_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        print("Flow\tSource IP\tSource Port\tDestination IP\tDestination Port\tDirection\tTimestamp (s)\tData Size")

        flow_windows = {}  # Dictionary to store flow windows

        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                continue

            ip = eth.data
            if ip.p != dpkt.ip.IP_PROTO_TCP:
                continue

            tcp = ip.data
            connection_id = (ip.src, tcp.sport, ip.dst, tcp.dport)
            reverse_connection_id = (ip.dst, tcp.dport, ip.src, tcp.sport)

            flow = connection_id_to_str(connection_id)
            reverse_flow = connection_id_to_str(reverse_connection_id)

            if flow in flow_windows:
                flow_windows[flow].append((ts, buf))
            elif reverse_flow in flow_windows:
                flow_windows[reverse_flow].append((ts, buf))
            else:
                flow_windows[flow] = [(ts, buf)]

        # Print flows in separate windows
        for flow, packets in flow_windows.items():
            forward_packets = 0
            backward_packets = 0
            start_time = packets[0][0]  # Get the timestamp of the first packet
            total_bytes_forward = 0
            total_bytes_backward = 0

            for ts, buf in packets:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                tcp = ip.data
                packet_size = len(tcp.data)  # Calculate the payload size excluding headers
                timestamp = ts - start_time  # Calculate the timestamp in seconds since the first captured packet

                if connection_id_to_str((ip.src, tcp.sport, ip.dst, tcp.dport)) == flow:
                    direction = "Forward"
                    forward_packets += 1
                    total_bytes_forward += packet_size
                else:
                    direction = "Backward"
                    backward_packets += 1
                    total_bytes_backward += packet_size

                print(f"{flow}\t{tcp.sport}\t{tcp.dport}\t{direction}\t{timestamp:.6f}\t{packet_size}")
            total_packets = forward_packets + backward_packets
            total_bytes = total_bytes_forward + total_bytes_backward
            
            print(f"\t{len(packets)} packets")
            print(f"\tTotal packets (A to B): {forward_packets}")
            print(f"\tTotal bytes (A to B): {total_bytes_forward}")
            print(f"\tTotal packets (B to A): {backward_packets}")
            print(f"\tTotal bytes (Back): {total_bytes_backward}")
            print(f"\tTotal bytes (Total): {total_bytes}\n")
            

analyze_pcap_file('E:\PPT Reader\http_ipv4_complex.cap')


# In[5]:


import dpkt
import socket

def connection_id_to_str(cid, v=4):
    """This converts the connection ID cid which is a tuple of (source_ip_address, source_tcp_port, destination_ip_address,
    destination_tcp_port) to a string. v is either 4 for IPv4 or 6 for IPv6"""
    if v == 4:
        src_ip_addr_str = socket.inet_ntoa(cid[0])
        dst_ip_addr_str = socket.inet_ntoa(cid[2])
        return src_ip_addr_str + ":" + str(cid[1]) + "<=>" + dst_ip_addr_str + ":" + str(cid[3])
    elif v == 6:
        src_ip_addr_str = socket.inet_ntop(socket.AF_INET6, cid[0])
        dst_ip_addr_str = socket.inet_ntop(socket.AF_INET6, cid[2])
        return src_ip_addr_str + "." + str(cid[1]) + "<=>" + dst_ip_addr_str + "." + str(cid[3])
    else:
        raise ValueError('Argument to connection_id_to_str must be 4 or 6, is %d' % v)

def analyze_pcap_file(file_path):
    """This function analyzes a pcap file and prints flow information"""
    with open(file_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        print("Flow\tSource IP\tSource Port\tDestination IP\tDestination Port\tDirection\tTimestamp (s)\tData Size")

        flow_windows = {}  # Dictionary to store flow windows

        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                continue

            ip = eth.data
            if ip.p != dpkt.ip.IP_PROTO_TCP:
                continue

            tcp = ip.data
            connection_id = (ip.src, tcp.sport, ip.dst, tcp.dport)
            reverse_connection_id = (ip.dst, tcp.dport, ip.src, tcp.sport)

            flow = connection_id_to_str(connection_id)
            reverse_flow = connection_id_to_str(reverse_connection_id)

            if flow in flow_windows:
                flow_windows[flow].append((ts, buf))
            elif reverse_flow in flow_windows:
                flow_windows[reverse_flow].append((ts, buf))
            else:
                flow_windows[flow] = [(ts, buf)]

        # Print flows in separate windows
        for flow, packets in flow_windows.items():
            forward_packets = 0
            backward_packets = 0
            start_time = packets[0][0]  # Get the timestamp of the first packet
            total_bytes_forward = 0
            total_bytes_backward = 0

            buckets = {}  # Dictionary to store packets in each bucket

            for ts, buf in packets:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                tcp = ip.data
                packet_size = len(tcp.data)  # Calculate the payload size excluding headers
                timestamp = ts - start_time  # Calculate the timestamp in seconds since the first captured packet

                if connection_id_to_str((ip.src, tcp.sport, ip.dst, tcp.dport)) == flow:
                    direction = "Forward"
                    forward_packets += 1
                    total_bytes_forward += packet_size
                else:
                    direction = "Backward"
                    backward_packets += 1
                    total_bytes_backward += packet_size

                # Determine the bucket for the current
                               
                bucket = int(timestamp)

                # Add packet to the bucket
                if bucket in buckets:
                    buckets[bucket].append((timestamp, buf))
                else:
                    buckets[bucket] = [(timestamp, buf)]

            # Process each bucket
            for bucket, bucket_packets in buckets.items():
                bucket_packet_count = len(bucket_packets)
                print(f"{flow}\t{tcp.sport}\t{tcp.dport}\t{direction}\t{bucket_packets[0][0]:.6f}\t{packet_size}\t{bucket_packet_count}")

            total_packets = forward_packets + backward_packets
            total_bytes = total_bytes_forward + total_bytes_backward

            print(f"\tTotal packets (A to B): {forward_packets}")
            print(f"\tTotal bytes (A to B): {total_bytes_forward}")
            print(f"\tTotal packets (B to A): {backward_packets}")
            print(f"\tTotal bytes (Back): {total_bytes_backward}")
            print(f"\tTotal bytes (Total): {total_bytes}\n")

analyze_pcap_file('E:\PPT Reader\http_ipv4_complex.cap')


# In[1]:


import dpkt
import socket

def connection_id_to_str(cid, v=4):
    """This converts the connection ID cid which is a tuple of (source_ip_address, source_tcp_port, destination_ip_address,
    destination_tcp_port) to a string. v is either 4 for IPv4 or 6 for IPv6"""
    if v == 4:
        src_ip_addr_str = socket.inet_ntoa(cid[0])
        dst_ip_addr_str = socket.inet_ntoa(cid[2])
        return src_ip_addr_str + ":" + str(cid[1]) + "<=>" + dst_ip_addr_str + ":" + str(cid[3])
    elif v == 6:
        src_ip_addr_str = socket.inet_ntop(socket.AF_INET6, cid[0])
        dst_ip_addr_str = socket.inet_ntop(socket.AF_INET6, cid[2])
        return src_ip_addr_str + "." + str(cid[1]) + "<=>" + dst_ip_addr_str + "." + str(cid[3])
    else:
        raise ValueError('Argument to connection_id_to_str must be 4 or 6, is %d' % v)

def analyze_pcap_file(file_path):
    """This function analyzes a pcap file and prints flow information"""
    with open(file_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        print("Flow\tSource IP\tSource Port\tDestination IP\tDestination Port\tDirection\tTimestamp (s)\tData Size")

        flow_windows = {}  # Dictionary to store flow windows

        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                continue

            ip = eth.data
            if ip.p != dpkt.ip.IP_PROTO_TCP:
                continue

            tcp = ip.data
            connection_id = (ip.src, tcp.sport, ip.dst, tcp.dport)
            reverse_connection_id = (ip.dst, tcp.dport, ip.src, tcp.sport)

            flow = connection_id_to_str(connection_id)
            reverse_flow = connection_id_to_str(reverse_connection_id)

            if flow in flow_windows:
                flow_windows[flow].append((ts, buf, tcp.sport, tcp.dport, "Forward"))
            elif reverse_flow in flow_windows:
                flow_windows[reverse_flow].append((ts, buf, tcp.sport, tcp.dport, "Backward"))
            else:
                flow_windows[flow] = [(ts, buf, tcp.sport, tcp.dport, "Forward")]

        # Process each flow window
        for flow, packets in flow_windows.items():
            buckets = {}  # Dictionary to store packets in each bucket

            forward_packets = 0
            backward_packets = 0
            total_bytes_forward = 0
            total_bytes_backward = 0

            for ts, buf, src_port, dst_port, direction in packets:
                # Calculate data size
                data_size = len(buf)

                # Adjust timestamp
                timestamp = ts - packets[0][0]

                # Increment counter for forward or backward packets
                if direction == "Forward":
                    forward_packets += 1
                    total_bytes_forward += data_size
                else:
                    backward_packets += 1
                    total_bytes_backward += data_size

                # Determine the bucket for the current packet
                bucket = int(timestamp)

                # Add packet to the bucket
                if bucket in buckets:
                    buckets[bucket].append((timestamp, buf, src_port, dst_port,dst_port, direction))
                else:
                    buckets[bucket] = [(timestamp, buf, src_port, dst_port, direction)]
                    # Print flows in separate windows
        print(f"Flow: {flow}")
        for bucket, packets in buckets.items():
            packet_count = len(packets)
            forward_packet_count = sum(1 for _, _, _, _, direction in packets if direction == "Forward")
            backward_packet_count = packet_count - forward_packet_count
            print(f"Bucket: {bucket}")
            print(f"Total Packets: {packet_count}")
            print(f"Forward Packets: {forward_packet_count}")
            print(f"Backward Packets: {backward_packet_count}")
            print()

        total_packets = forward_packets + backward_packets
        total_bytes = total_bytes_forward + total_bytes_backward

        print(f"Flow Summary - {flow}")
        print(f"Total Packets (Forward): {forward_packets}")
        print(f"Total Packets (Backward): {backward_packets}")
        print(f"Total Bytes (Forward): {total_bytes_forward}")
        print(f"Total Bytes (Backward): {total_bytes_backward}")
        print(f"Total Bytes (Total): {total_bytes}\n")
analyze_pcap_file('E:\PPT Reader\http_ipv4_complex.cap')



# In[8]:


import dpkt
import socket

def connection_id_to_str(cid, v=4):
    """This converts the connection ID cid which is a tuple of (source_ip_address, source_tcp_port, destination_ip_address,
    destination_tcp_port) to a string. v is either 4 for IPv4 or 6 for IPv6"""
    if v == 4:
        src_ip_addr_str = socket.inet_ntoa(cid[0])
        dst_ip_addr_str = socket.inet_ntoa(cid[2])
        return src_ip_addr_str + ":" + str(cid[1]) + "<=>" + dst_ip_addr_str + ":" + str(cid[3])
    elif v == 6:
        src_ip_addr_str = socket.inet_ntop(socket.AF_INET6, cid[0])
        dst_ip_addr_str = socket.inet_ntop(socket.AF_INET6, cid[2])
        return src_ip_addr_str + "." + str(cid[1]) + "<=>" + dst_ip_addr_str + "." + str(cid[3])
    else:
        raise ValueError('Argument to connection_id_to_str must be 4 or 6, is %d' % v)

def analyze_pcap_file(file_path):
    """This function analyzes a pcap file and prints flow information"""
    with open(file_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        print("Flow\tSource IP\tSource Port\tDestination IP\tDestination Port\tDirection\tTimestamp (s)\tData Size")

        flow_windows = {}  # Dictionary to store flow windows

        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                continue

            ip = eth.data
            if ip.p != dpkt.ip.IP_PROTO_TCP:
                continue

            tcp = ip.data
            connection_id = (ip.src, tcp.sport, ip.dst, tcp.dport)
            reverse_connection_id = (ip.dst, tcp.dport, ip.src, tcp.sport)

            flow = connection_id_to_str(connection_id)
            reverse_flow = connection_id_to_str(reverse_connection_id)

            if flow in flow_windows:
                flow_windows[flow].append((ts, buf, tcp.sport, tcp.dport))
            elif reverse_flow in flow_windows:
                flow_windows[reverse_flow].append((ts, buf, tcp.sport, tcp.dport))
            else:
                flow_windows[flow] = [(ts, buf, tcp.sport, tcp.dport)]

        # Print flows in separate windows
        for flow, packets in flow_windows.items():
            forward_packets = 0
            backward_packets = 0
            start_time = packets[0][0]  # Get the timestamp of the first packet
            total_bytes_forward = 0
            total_bytes_backward = 0

            buckets = {}  # Dictionary to store packets in each bucket

            for ts, buf, src_port, dst_port in packets:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                tcp = ip.data
                packet_size = len(tcp.data)  # Calculate the payload size excluding headers
                timestamp = ts - start_time  # Calculate the timestamp in seconds since the first captured packet

                if connection_id_to_str((ip.src, tcp.sport, ip.dst, tcp.dport)) == flow:
                    direction = "Forward"
                    forward_packets += 1
                    total_bytes_forward += packet_size
                else:
                    direction = "Backward"
                    backward_packets += 1
                    total_bytes_backward += packet_size

                # Determine the bucket for the current packet
                bucket = int(timestamp)

                # Add packet to the bucket
                if bucket in buckets:
                    buckets[bucket].append((timestamp, packet_size, direction))
                else:
                    buckets[bucket] = [(timestamp, packet_size, direction)]

            # Print packet information in each bucket
            for bucket, packet_info in buckets.items():
                packet_count = len(packet_info)
                forward_packet_count = sum(1 for _, _, direction in packet_info if direction == "Forward")
                backward_packet_count = packet_count - forward_packet_count
                print(f"{flow}\t{forward_packet_count}\t{backward_packet_count}\t{direction}\t{timestamp}")

            total_packets = forward_packets + backward_packets
            total_bytes = total_bytes_forward + total_bytes_backward

            print(f"\tTotal packets (A to B): {forward_packets}")
            print(f"\tTotal bytes (A to B): {total_bytes_forward}")
            print(f"\tTotal packets (B to A): {backward_packets}")
            print(f"\tTotal bytes (B to A): {total_bytes_backward}")
            print(f"\tTotal bytes (Total): {total_bytes}\n")
           
        
analyze_pcap_file('E:\PPT Reader\http_ipv4_complex.cap')


# In[4]:


import dpkt
import socket

def connection_id_to_str(cid, v=4):
    """This converts the connection ID cid which is a tuple of (source_ip_address, source_tcp_port, destination_ip_address,
    destination_tcp_port) to a string. v is either 4 for IPv4 or 6 for IPv6"""
    if v == 4:
        src_ip_addr_str = socket.inet_ntoa(cid[0])
        dst_ip_addr_str = socket.inet_ntoa(cid[2])
        return src_ip_addr_str + ":" + str(cid[1]) + "<=>" + dst_ip_addr_str + ":" + str(cid[3])
    elif v == 6:
        src_ip_addr_str = socket.inet_ntop(socket.AF_INET6, cid[0])
        dst_ip_addr_str = socket.inet_ntop(socket.AF_INET6, cid[2])
        return src_ip_addr_str + "." + str(cid[1]) + "<=>" + dst_ip_addr_str + "." + str(cid[3])
    else:
        raise ValueError('Argument to connection_id_to_str must be 4 or 6, is %d' % v)

def analyze_pcap_file(file_path):
    """This function analyzes a pcap file and prints flow information"""
    with open(file_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        print("Flow\tSource IP\tSource Port\tDestination IP\tDestination Port\tDirection\tTimestamp (s)\tData Size")

        flow_windows = {}  # Dictionary to store flow windows

        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                continue

            ip = eth.data
            if ip.p != dpkt.ip.IP_PROTO_TCP:
                continue

            tcp = ip.data
            connection_id = (ip.src, tcp.sport, ip.dst, tcp.dport)
            reverse_connection_id = (ip.dst, tcp.dport, ip.src, tcp.sport)

            flow = connection_id_to_str(connection_id)
            reverse_flow = connection_id_to_str(reverse_connection_id)

            if flow in flow_windows:
                flow_windows[flow].append((ts, buf))
            elif reverse_flow in flow_windows:
                flow_windows[reverse_flow].append((ts, buf))
            else:
                flow_windows[flow] = [(ts, buf)]

        # Print flows in separate windows
        for flow, packets in flow_windows.items():
            forward_packets = 0
            backward_packets = 0
            start_time = packets[0][0]  # Get the timestamp of the first packet
            total_bytes_forward = 0
            total_bytes_backward = 0

            for ts, buf in packets:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                tcp = ip.data
                packet_size = len(tcp.data)  # Calculate the payload size excluding headers
                timestamp = ts - start_time  # Calculate the timestamp in seconds since the first captured packet

                if connection_id_to_str((ip.src, tcp.sport, ip.dst, tcp.dport)) == flow:
                    direction = "Forward"
                    forward_packets += 1
                    total_bytes_forward += packet_size
                else:
                    direction = "Backward"
                    backward_packets += 1
                    total_bytes_backward += packet_size

                print(f"{flow}\t{tcp.sport}\t{tcp.dport}\t{direction}\t{timestamp:.6f}\t{packet_size}")
            
            total_packets = forward_packets + backward_packets
            total_bytes = total_bytes_forward + total_bytes_backward
            
            print(f"\tTotal packets (Forward): {forward_packets}")
            print(f"\tTotal bytes (Forward): {total_bytes_forward}")
            print(f"\tTotal packets (Backward): {backward_packets}")
            print(f"\tTotal bytes (Backward): {total_bytes_backward}")
            print(f"\tTotal packets: {total_packets}")
            print(f"\tTotal bytes: {total_bytes}\n")
            
analyze_pcap_file('E:\PPT Reader\http_ipv4_complex.cap')


# In[9]:


import dpkt
import socket

def connection_id_to_str(cid, v=4):
    """This converts the connection ID cid which is a tuple of (source_ip_address, source_tcp_port, destination_ip_address,
    destination_tcp_port) to a string. v is either 4 for IPv4 or 6 for IPv6"""
    if v == 4:
        src_ip_addr_str = socket.inet_ntoa(cid[0])
        dst_ip_addr_str = socket.inet_ntoa(cid[2])
        return src_ip_addr_str + ":" + str(cid[1]) + "<=>" + dst_ip_addr_str + ":" + str(cid[3])
    elif v == 6:
        src_ip_addr_str = socket.inet_ntop(socket.AF_INET6, cid[0])
        dst_ip_addr_str = socket.inet_ntop(socket.AF_INET6, cid[2])
        return src_ip_addr_str + "." + str(cid[1]) + "<=>" + dst_ip_addr_str + "." + str(cid[3])
    else:
        raise ValueError('Argument to connection_id_to_str must be 4 or 6, is %d' % v)
def analyze_pcap_file(file_path):
    """This function analyzes a pcap file and prints flow information"""
    with open(file_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        print("Flow\tSource IP\tSource Port\tDestination IP\tDestination Port\tDirection\tTimestamp (s)\tData Size")

        flow_windows = {}  # Dictionary to store flow windows

        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                continue

            ip = eth.data
            if ip.p != dpkt.ip.IP_PROTO_TCP:
                continue

            tcp = ip.data
            connection_id = (ip.src, tcp.sport, ip.dst, tcp.dport)
            reverse_connection_id = (ip.dst, tcp.dport, ip.src, tcp.sport)

            flow = connection_id_to_str(connection_id)
            reverse_flow = connection_id_to_str(reverse_connection_id)

            if flow in flow_windows:
                flow_windows[flow].append((ts, buf))
            elif reverse_flow in flow_windows:
                flow_windows[reverse_flow].append((ts, buf))
            else:
                flow_windows[flow] = [(ts, buf)]

        # Print flows in separate windows
        for flow, packets in flow_windows.items():
            forward_packets = 0
            backward_packets = 0
            start_time = packets[0][0]  # Get the timestamp of the first packet
            total_bytes_forward = 0
            total_bytes_backward = 0

            buckets = set()  # Set to store unique bucket numbers within the flow

            for ts, buf in packets:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                tcp = ip.data
                packet_size = len(tcp.data)  # Calculate the payload size excluding headers
                timestamp = ts - start_time  # Calculate the timestamp in seconds since the first captured packet

                if connection_id_to_str((ip.src, tcp.sport, ip.dst, tcp.dport)) == flow:
                    direction = "Forward"
                    forward_packets += 1
                    total_bytes_forward += packet_size
                else:
                    direction = "Backward"
                    backward_packets += 1
                    total_bytes_backward += packet_size

                bucket = int(timestamp)  # Get the bucket number
                buckets.add(bucket)  # Add the bucket number to the set

                print(f"{flow}\t{tcp.sport}\t{tcp.dport}\t{direction}\t{timestamp:.6f}\t{packet_size}")

            total_packets = forward_packets + backward_packets
            total_bytes = total_bytes_forward + total_bytes_backward

            print(f"\tTotal packets (Forward): {forward_packets}")
            print(f"\tTotal bytes (Forward): {total_bytes_forward}")
            print(f"\tTotal packets (Backward): {backward_packets}")
            print(f"\tTotal bytes (Backward): {total_bytes_backward}")
            print(f"\tTotal packets: {total_packets}")
            print(f"\tTotal bytes: {total_bytes}")
            print(f"\tNumber of buckets: {len(buckets)}\n")

analyze_pcap_file('E:\PPT Reader\http_ipv4_complex.cap')


# In[13]:


import dpkt
import socket

def connection_id_to_str(cid, v=4):
    """This converts the connection ID cid which is a tuple of (source_ip_address, source_tcp_port, destination_ip_address,
    destination_tcp_port) to a string. v is either 4 for IPv4 or 6 for IPv6"""
    if v == 4:
        src_ip_addr_str = socket.inet_ntoa(cid[0])
        dst_ip_addr_str = socket.inet_ntoa(cid[2])
        return src_ip_addr_str + ":" + str(cid[1]) + "<=>" + dst_ip_addr_str + ":" + str(cid[3])
    elif v == 6:
        src_ip_addr_str = socket.inet_ntop(socket.AF_INET6, cid[0])
        dst_ip_addr_str = socket.inet_ntop(socket.AF_INET6, cid[2])
        return src_ip_addr_str + "." + str(cid[1]) + "<=>" + dst_ip_addr_str + "." + str(cid[3])
    else:
        raise ValueError('Argument to connection_id_to_str must be 4 or 6, is %d' % v)
def analyze_pcap_file(file_path):
    """This function analyzes a pcap file and prints flow information"""
    with open(file_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        print("Flow\tForward Packets\tBackward Packets\tTotal Bytes per Second\tTotal Forward Bytes\tTotal Backward Bytes\tForward Inter-arrival Time\tBackward Inter-arrival Time\tFlow Inter-arrival Time")

        flow_windows = {}  # Dictionary to store flow windows

        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                continue

            ip = eth.data
            if ip.p != dpkt.ip.IP_PROTO_TCP:
                continue

            tcp = ip.data
            connection_id = (ip.src, tcp.sport, ip.dst, tcp.dport)
            reverse_connection_id = (ip.dst, tcp.dport, ip.src, tcp.sport)

            flow = connection_id_to_str(connection_id)
            reverse_flow = connection_id_to_str(reverse_connection_id)

            if flow in flow_windows:
                flow_windows[flow].append((ts, buf, tcp.sport, tcp.dport))
            elif reverse_flow in flow_windows:
                flow_windows[reverse_flow].append((ts, buf, tcp.sport, tcp.dport))
            else:
                flow_windows[flow] = [(ts, buf, tcp.sport, tcp.dport)]

        # Print flows in separate windows
        for flow, packets in flow_windows.items():
            forward_packets = 0
            backward_packets = 0
            start_time = packets[0][0]  # Get the timestamp of the first packet
            total_bytes_forward = 0
            total_bytes_backward = 0

            buckets = {}  # Dictionary to store packets in each bucket

            for ts, buf, src_port, dst_port in packets:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                tcp = ip.data
                packet_size = len(tcp.data)  # Calculate the payload size excluding headers
                timestamp = ts - start_time  # Calculate the timestamp in seconds since the first captured packet

                if connection_id_to_str((ip.src, tcp.sport, ip.dst, tcp.dport)) == flow:
                    direction = "Forward"
                    forward_packets += 1
                    total_bytes_forward += packet_size
                else:
                    direction = "Backward"
                    backward_packets += 1
                    total_bytes_backward += packet_size

                # Determine the bucket for the current packet
                bucket = int(timestamp)

                # Add packet to the bucket
                if bucket in buckets:
                    buckets[bucket].append((timestamp, packet_size, direction))
                else:
                    buckets[bucket] = [(timestamp, packet_size, direction)]

            # Print packet information in each bucket
            for bucket, packet_info in buckets.items():
                packet_count = len(packet_info)
                forward_packet_count = sum(1 for _, _, direction in packet_info if direction == "Forward")
                backward_packet_count = packet_count - forward_packet_count
                forward_bytes_per_sec = total_bytes_forward / bucket if bucket > 0 else 0

                backward_bytes_per_sec = total_bytes_forward / bucket if bucket > 0 else 0

                forward_inter_arrival_time = 0 if forward_packet_count == 1 else (packet_info[-1][0] - packet_info[0][0]) / (forward_packet_count - 1)
                backward_inter_arrival_time = 0 if backward_packet_count == 1 else (packet_info[-1][0] - packet_info[0][0]) / (backward_packet_count - 1)
                flow_inter_arrival_time = packet_info[-1][0] - packet_info[0][0]

                print(f"{flow}\t{forward_packet_count}\t{backward_packet_count}\t{forward_bytes_per_sec}\t{total_bytes_forward}\t{total_bytes_backward}\t{forward_inter_arrival_time}\t{backward_inter_arrival_time}\t{flow_inter_arrival_time}")

            total_packets = forward_packets + backward_packets
            total_bytes = total_bytes_forward + total_bytes_backward

            print(f"\tTotal packets (A to B): {forward_packets}")
            print(f"\tTotal bytes (A to B): {total_bytes_forward}")
            print(f"\tTotal packets (B to A): {backward_packets}")
            print(f"\tTotal bytes (B to A): {total_bytes_backward}")
            print(f"\tTotal bytes (Total): {total_bytes}\n")

analyze_pcap_file('E:\PPT Reader\http_ipv4_complex.cap')


# In[3]:


import dpkt
import socket

def connection_id_to_str(cid, v=4):
    """This converts the connection ID cid which is a tuple of (source_ip_address, source_tcp_port, destination_ip_address,
    destination_tcp_port) to a string. v is either 4 for IPv4 or 6 for IPv6"""
    if v == 4:
        src_ip_addr_str = socket.inet_ntoa(cid[0])
        dst_ip_addr_str = socket.inet_ntoa(cid[2])
        return src_ip_addr_str + ":" + str(cid[1]) + "<=>" + dst_ip_addr_str + ":" + str(cid[3])
    elif v == 6:
        src_ip_addr_str = socket.inet_ntop(socket.AF_INET6, cid[0])
        dst_ip_addr_str = socket.inet_ntop(socket.AF_INET6, cid[2])
        return src_ip_addr_str + "." + str(cid[1]) + "<=>" + dst_ip_addr_str + "." + str(cid[3])
    else:
        raise ValueError('Argument to connection_id_to_str must be 4 or 6, is %d' % v)

def analyze_pcap_file(file_path):
    """This function analyzes a pcap file and prints flow information"""
    with open(file_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        print("Flow\tForward Packets\tBackward Packets\tBytes per Second\tTotal Forward Bytes\tTotal Backward Bytes\tForward Inter-arrival Time\tBackward Inter-arrival Time\tFlow Inter-arrival Time")

        flow_windows = {}  # Dictionary to store flow windows

        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                continue

            ip = eth.data
            if ip.p != dpkt.ip.IP_PROTO_TCP:
                continue

            tcp = ip.data
            connection_id = (ip.src, tcp.sport, ip.dst, tcp.dport)
            reverse_connection_id = (ip.dst, tcp.dport, ip.src, tcp.sport)

            flow = connection_id_to_str(connection_id)
            reverse_flow = connection_id_to_str(reverse_connection_id)

            if flow in flow_windows:
                flow_windows[flow].append((ts, buf, tcp.sport, tcp.dport))
            elif reverse_flow in flow_windows:
                flow_windows[reverse_flow].append((ts, buf, tcp.sport, tcp.dport))
            else:
                flow_windows[flow] = [(ts, buf, tcp.sport, tcp.dport)]

        # Print flows in separate windows
        for flow, packets in flow_windows.items():
            forward_packets = 0
            backward_packets = 0
            start_time = packets[0][0]  # Get the timestamp of the first packet
            total_bytes_forward = 0
            total_bytes_backward = 0

            buckets = {}  # Dictionary to store packets in each bucket

            for ts, buf, src_port, dst_port in packets:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                tcp = ip.data
                packet_size = len(tcp.data)  # Calculate the payload size excluding headers
                timestamp = ts - start_time  # Calculate the timestamp in seconds since the first captured packet

                if connection_id_to_str((ip.src, tcp.sport, ip.dst, tcp.dport)) == flow:
                    direction = "Forward"
                    forward_packets += 1 
                    total_bytes_forward += packet_size
                else:
                    direction= "Backward"
                    backward_packets += 1
                    total_bytes_backward += packet_size
            # Determine the bucket for the current packet
            bucket = int(timestamp)

            # Add packet to the bucket
            if bucket in buckets:
                buckets[bucket].append((timestamp, packet_size, direction))
            else:
                buckets[bucket] = [(timestamp, packet_size, direction)]

        # Process each bucket
        for bucket, packet_info in buckets.items():
            packet_count = len(packet_info)

            # Discard the bucket if it has less than 20 packets
            if packet_count < 20:
                continue

            forward_packet_count = sum(1 for _, _, direction in packet_info if direction == "Forward")
            backward_packet_count = packet_count - forward_packet_count

            forward_bytes_per_sec = total_bytes_forward / bucket
            backward_bytes_per_sec = total_bytes_backward / bucket

            forward_interarrival_time = 0
            backward_interarrival_time = 0
            flow_interarrival_time = 0

            if packet_count > 1:
                forward_interarrival_time = (packet_info[-1][0] - packet_info[0][0]) / (forward_packet_count - 1)
                backward_interarrival_time = (packet_info[-1][0] - packet_info[0][0]) / (backward_packet_count - 1)
                flow_interarrival_time = (packet_info[-1][0] - packet_info[0][0]) / (packet_count - 1)

            print(f"{flow}\t{forward_packet_count}\t{backward_packet_count}\t{forward_bytes_per_sec:.2f}\t{total_bytes_forward}\t{total_bytes_backward}\t{forward_interarrival_time:.6f}\t{backward_interarrival_time:.6f}\t{flow_interarrival_time:.6f}")

        total_packets = forward_packets + backward_packets
        total_bytes = total_bytes_forward + total_bytes_backward

        print(f"\tTotal packets (A to B): {forward_packets}")
        print(f"\tTotal bytes (A to B): {total_bytes_forward}")
        print(f"\tTotal packets (B to A): {backward_packets}")
        print(f"\tTotal bytes (B to A): {total_bytes_backward}")
        print(f"\tTotal bytes (Total): {total_bytes}\n")
        
        
analyze_pcap_file('E:\PPT Reader\http_ipv4_complex.cap')     


# In[9]:


import dpkt
import socket

def connection_id_to_str(cid, v=4):
    """This converts the connection ID cid which is a tuple of (source_ip_address, source_tcp_port, destination_ip_address,
    destination_tcp_port) to a string. v is either 4 for IPv4 or 6 for IPv6"""
    if v == 4:
        src_ip_addr_str = socket.inet_ntoa(cid[0])
        dst_ip_addr_str = socket.inet_ntoa(cid[2])
        return src_ip_addr_str + ":" + str(cid[1]) + "<=>" + dst_ip_addr_str + ":" + str(cid[3])
    elif v == 6:
        src_ip_addr_str = socket.inet_ntop(socket.AF_INET6, cid[0])
        dst_ip_addr_str = socket.inet_ntop(socket.AF_INET6, cid[2])
        return src_ip_addr_str + "." + str(cid[1]) + "<=>" + dst_ip_addr_str + "." + str(cid[3])
    else:
        raise ValueError('Argument to connection_id_to_str must be 4 or 6, is %d' % v)

def analyze_pcap_file(file_path):
    """This function analyzes a pcap file and prints flow information"""
    with open(file_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        print("Flow\tForward Packets\tBackward Packets\tBytes per Second\tTotal Forward Bytes\tTotal Backward Bytes\tForward Inter-arrival Time\tBackward Inter-arrival Time\tFlow Inter-arrival Time\tState")

        flow_windows = {}  # Dictionary to store flow windows
        flow_states = {}  # Dictionary to store flow states (active or idle)

        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                continue

            ip = eth.data
            if ip.p != dpkt.ip.IP_PROTO_TCP:
                continue

            tcp = ip.data
            connection_id = (ip.src, tcp.sport, ip.dst, tcp.dport)
            reverse_connection_id = (ip.dst, tcp.dport, ip.src, tcp.sport)

            flow = connection_id_to_str(connection_id)
            reverse_flow = connection_id_to_str(reverse_connection_id)

            if flow in flow_windows:
                flow_windows[flow].append((ts, buf, tcp.sport, tcp.dport, tcp.flags))
            elif reverse_flow in flow_windows:
                flow_windows[reverse_flow].append((ts, buf, tcp.sport, tcp.dport, tcp.flags))
            else:
                flow_windows[flow] = [(ts, buf, tcp.sport, tcp.dport, tcp.flags)]

        # Determine flow states (active or idle) based on SYN and FIN flags
        for flow, packets in flow_windows.items():
            is_active = False
            is_idle = False

            for _, _, _, _, flags in packets:
                if flags & dpkt.tcp.TH_SYN != 0 and flags & dpkt.tcp.TH_FIN == 0:
                    is_active = True
                if flags & dpkt.tcp.TH_FIN != 0:
                    is_idle = True

            #if is_active and is_idle:
             #   flow_states[flow] = "Active and Idle"
            if is_active:
                flow_states[flow] = "Active"
            elif is_idle:
                flow_states[flow] = "Idle"
            else:
                flow_states[flow] = "Unknown"

        # Print flow information and state
        for flow, packets in flow_windows.items():
            forward_packets = 0
            backward_packets = 0
            start_time = packets[0][0]  # Get the timestamp of the first packet
            total_bytes_forward = 0
            total_bytes_backward = 0

            buckets = {}  # Dictionary to store packets in each bucket

            for ts, buf, src_port, dst_port, flags in packets:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                tcp = ip.data
                packet_size = len(tcp.data)  # Calculate the payload size excluding headers
                timestamp = ts - start_time  # Calculate the timestamp in seconds since the first captured packet

                if connection_id_to_str((ip.src, tcp.sport, ip.dst, tcp.dport)) == flow:
                    direction = "Forward"
                    forward_packets += 1
                    total_bytes_forward += packet_size
                else:
                    direction = "Backward"
                    backward_packets += 1
                    total_bytes_backward += packet_size

                # Assign the state of the flow
                state = flow_states[flow]
                            # Add packet to the corresponding bucket
                bucket = int(timestamp)  # Use the timestamp as the bucket key
                if bucket in buckets:
                    buckets[bucket].append((ts, packet_size, direction, flags))
                else:
                    buckets[bucket] = [(ts, packet_size, direction, flags)]

        # Print packet information in each bucket
        for bucket, packet_info in buckets.items():
            #if len(packet_info) < 20:
             #   continue

            packet_count = len(packet_info)
            forward_packet_count = sum(1 for _, _, direction, _ in packet_info if direction == "Forward")
            backward_packet_count = packet_count - forward_packet_count

            # Calculate total bytes per second
            total_bytes_forward = sum(
                packet_size for _, packet_size, direction, _ in packet_info if direction == "Forward")
            total_bytes_backward = sum(
                packet_size for _, packet_size, direction, _ in packet_info if direction == "Backward")
            forward_bytes_per_sec = total_bytes_forward / bucket if bucket > 0 else 0

            # Calculate inter-arrival times
            inter_arrival_times = [packet_info[i + 1][0] - packet_info[i][0] for i in range(packet_count - 1)]
            forward_inter_arrival_time = sum(
                inter_arrival_times[i]
                for i, (_, _, direction, _) in enumerate(packet_info[:-1])
                if direction == "Forward" ) / forward_packet_count if forward_packet_count > 0 else 0

            backward_inter_arrival_time = sum(
                inter_arrival_times[i]
                for i, (_, _, direction, _) in enumerate(packet_info[:-1])
                if direction == "Backward") / backward_packet_count if backward_packet_count > 0 else 0

            flow_inter_arrival_time = packet_info[-1][0] - packet_info[0][0]

            print(
                f"{flow}\t{forward_packet_count}\t{backward_packet_count}\t{forward_bytes_per_sec}\t{total_bytes_forward}\t{total_bytes_backward}\t{forward_inter_arrival_time}\t{backward_inter_arrival_time}\t{flow_inter_arrival_time}\t\t{state}")

        total_packets = forward_packets + backward_packets
        total_bytes = total_bytes_forward + total_bytes_backward

        print(f"\tTotal packets (A to B): {forward_packets}")
        print(f"\tTotal bytes (A to B): {total_bytes_forward}")
        print(f"\tTotal packets (B to A): {backward_packets}")
        print(f"\tTotal bytes (B to A): {total_bytes_backward}")
        print(f"\tTotal bytes (Total): {total_bytes}\n")

analyze_pcap_file('E:\PPT Reader\http_ipv4_complex.cap')     


# In[18]:


import dpkt
import socket

def connection_id_to_str(cid, v=4):
    """This converts the connection ID cid which is a tuple of (source_ip_address, source_tcp_port, destination_ip_address,
    destination_tcp_port) to a string. v is either 4 for IPv4 or 6 for IPv6"""
    if v == 4:
        src_ip_addr_str = socket.inet_ntoa(cid[0])
        dst_ip_addr_str = socket.inet_ntoa(cid[2])
        return src_ip_addr_str + ":" + str(cid[1]) + "<=>" + dst_ip_addr_str + ":" + str(cid[3])
    elif v == 6:
        src_ip_addr_str = socket.inet_ntop(socket.AF_INET6, cid[0])
        dst_ip_addr_str = socket.inet_ntop(socket.AF_INET6, cid[2])
        return src_ip_addr_str + "." + str(cid[1]) + "<=>" + dst_ip_addr_str + "." + str(cid[3])
    else:
        raise ValueError('Argument to connection_id_to_str must be 4 or 6, is %d' % v)
def analyze_pcap_file(file_path):
    with open(file_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        print("Flow\tActive (s)\tIdle (s)")

        flow_windows = {}
        flow_states = {}

        for ts, buf in pcap:
           
            eth = dpkt.ethernet.Ethernet(buf)
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                continue

            ip = eth.data
            if ip.p != dpkt.ip.IP_PROTO_TCP:
                continue

            tcp = ip.data
            connection_id = (ip.src, tcp.sport, ip.dst, tcp.dport)
            reverse_connection_id = (ip.dst, tcp.dport, ip.src, tcp.sport)

            flow = connection_id_to_str(connection_id)
            reverse_flow = connection_id_to_str(reverse_connection_id)

            if flow in flow_windows:
                flow_windows[flow].append((ts, buf, tcp.sport, tcp.dport, tcp.flags))
            elif reverse_flow in flow_windows:
                flow_windows[reverse_flow].append((ts, buf, tcp.sport, tcp.dport, tcp.flags))
            else:
                flow_windows[flow] = [(ts, buf, tcp.sport, tcp.dport, tcp.flags)]
        for flow, packets in flow_windows.items():
            is_active = False
            is_idle = False
            active_duration = 0
            idle_duration = 0
            last_timestamp = packets[0][0]

            for  flags in packets:
                if flags & dpkt.tcp.TH_SYN != 0 and flags & dpkt.tcp.TH_FIN == 0:
                    if not is_active:
                        is_active = True
                        active_start_time = ts
                    if is_idle:
                        idle_duration += ts - last_timestamp
                        is_idle = False
                if flags & dpkt.tcp.TH_FIN != 0:
                    if is_active:
                        active_duration += ts - active_start_time
                        is_active = False
                    if not is_idle:
                        is_idle = True
                        last_timestamp = ts

            # Check if flow is still active at the end of the pcap
            if is_active:
                active_duration += ts - active_start_time
            elif is_idle:
                idle_duration += ts - last_timestamp

            # Convert active and idle durations to seconds
            active_duration = active_duration if is_active else 0
            idle_duration = idle_duration if is_idle else 0

            flow_states[flow] = (active_duration, idle_duration)

        # Print flow states in seconds
        for flow, (active_duration, idle_duration) in flow_states.items():
            print(f"{flow}\t{active_duration:.2f}\t{idle_duration:.2f}")

analyze_pcap_file('E:\PPT Reader\http_ipv4_complex.cap')


# In[ ]:




