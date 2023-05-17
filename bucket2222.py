#!/usr/bin/env python
# coding: utf-8

# In[17]:


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
        print("Windows\tFlow\tTimestamp\tDirection\tData Size\tSYN\tFIN")  ##bucket as window i have change the name of window
                                                                           #  as bucket for my preference of understanding.....

        flow_buckets = {}  # Dictionary to store flow buckets

        first_ts = None  # Variable to store the timestamp of the first packet

        for ts, buf in pcap:
            if first_ts is None: #if timestamp is  none then current timestamp will be first timestamp.
                first_ts = ts  # Set the timestamp of the first captured packet

            eth = dpkt.ethernet.Ethernet(buf)  #buf is 
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

            bucket_index = int((ts - first_ts) // 1)  # Calculate the bucket index

            if bucket_index in flow_buckets:
                if flow in flow_buckets[bucket_index]:
                    flow_buckets[bucket_index][flow].append((ts, buf, tcp.sport, tcp.dport, len(tcp.data), tcp.flags))
                elif reverse_flow in flow_buckets[bucket_index]:
                    flow_buckets[bucket_index][reverse_flow].append((ts, buf, tcp.sport, tcp.dport, len(tcp.data), tcp.flags))
                else:
                    flow_buckets[bucket_index][flow] = [(ts, buf, tcp.sport, tcp.dport, len(tcp.data), tcp.flags)]
            else:
                flow_buckets[bucket_index] = {flow: [(ts, buf, tcp.sport, tcp.dport, len(tcp.data), tcp.flags)]}

        # Print flow buckets
        for bucket_index, flows in flow_buckets.items():
            for flow, packets in flows.items():
                flow_info = []
                for idx, (ts, buf, src_port, dst_port, data_size, flags) in enumerate(packets):
                    eth = dpkt.ethernet.Ethernet(buf)
                    ip = eth.data
                    tcp = ip.data
                    direction = 1 if connection_id_to_str((ip.src, tcp.sport, ip.dst, tcp.dport)) == flow else -1
                    if idx == 0:
                        timestamp = ts - first_ts
                    else:
                        timestamp = ts - first_ts  # Calculate the timestamp in seconds since the first captured packet
                    flag_names = []
                    if flags & dpkt.tcp.TH_SYN:
                        flag_names.append("SYN")
                    if flags & dpkt.tcp.TH_FIN:
                        flag_names.append("FIN")
                    flow_info.append([timestamp, direction, data_size, flag_names])
                print(f"{bucket_index}\t{flow}\t{flow_info}")

analyze_pcap_file('E:\PPT Reader\http_ipv4_complex.cap')


# Windows	Flow	Timestamp	Direction	Data Size	SYN	FIN
# 0	192.168.1.104:41849<=>67.205.52.141:80	[[0.0, 1, 0, ['SYN']], [0.052906036376953125, -1, 0, ['SYN']], [0.05294084548950195, 1, 0, []], [0.052983999252319336, 1, 394, []], [0.11489295959472656, -1, 0, []], [0.11852192878723145, -1, 1448, []], [0.11853599548339844, 1, 0, []], [0.11969304084777832, -1, 1448, []], [0.11970996856689453, 1, 0, []], [0.12064886093139648, -1, 1448, []], [0.12066006660461426, 1, 0, []], [0.15792107582092285, -1, 1448, []], [0.15794801712036133, 1, 0, []], [0.16084790229797363, -1, 1448, []], [0.16086697578430176, 1, 0, []], [0.16356396675109863, -1, 1448, []], [0.1635758876800537, 1, 0, []], [0.16584992408752441, -1, 1448, []], [0.16586089134216309, 1, 0, []], [0.16829490661621094, -1, 1448, []], [0.1683049201965332, 1, 0, []], [0.17022991180419922, -1, 1289, []], [0.17024803161621094, 1, 0, []], [0.20525884628295898, 1, 452, []], [0.2444610595703125, -1, 496, []], [0.24945998191833496, 1, 421, []], [0.28720784187316895, -1, 495, []], [0.2873108386993408, 1, 425, []], [0.32711005210876465, -1, 502, []], [0.32723307609558105, 1, 423, []], [0.3706519603729248, -1, 498, []], [0.37079286575317383, 1, 424, []], [0.4094369411468506, -1, 498, []], [0.4096200466156006, 1, 419, []], [0.4471158981323242, -1, 495, []], [0.48822689056396484, 1, 0, []], [0.639970064163208, 1, 421, []], [0.6809289455413818, -1, 495, []], [0.6809430122375488, 1, 0, []], [0.6810150146484375, 1, 419, []], [0.7179288864135742, -1, 495, []], [0.7597248554229736, 1, 0, []]]
# 0	192.168.1.104:41850<=>67.205.52.141:80	[[0.20777392387390137, 1, 0, ['SYN']], [0.249237060546875, -1, 0, ['SYN']], [0.24925684928894043, 1, 0, []], [0.24938392639160156, 1, 426, []], [0.28623104095458984, -1, 0, []], [0.3043830394744873, -1, 1448, []], [0.30440306663513184, 1, 0, []], [0.3060338497161865, -1, 1448, []], [0.3060438632965088, 1, 0, []], [0.3069939613342285, -1, 1448, []], [0.3070030212402344, 1, 0, []], [0.3428220748901367, -1, 1448, []], [0.34283900260925293, 1, 0, []], [0.34386301040649414, -1, 1448, []], [0.34387993812561035, 1, 0, []], [0.346904993057251, -1, 1448, []], [0.34691691398620605, 1, 0, []], [0.34802889823913574, -1, 1448, []], [0.3480379581451416, 1, 0, []], [0.3494069576263428, -1, 1448, []], [0.34941697120666504, 1, 0, []], [0.35040783882141113, -1, 1448, []], [0.3504209518432617, 1, 0, []], [0.38700103759765625, -1, 1448, []], [0.3870229721069336, 1, 0, []], [0.3917560577392578, -1, 1448, []], [0.39177894592285156, 1, 0, []], [0.3948628902435303, -1, 1448, []], [0.39487695693969727, 1, 0, []], [0.3967628479003906, -1, 176, []], [0.3967759609222412, 1, 0, []], [0.396867036819458, 1, 415, []], [0.4540748596191406, -1, 1448, []], [0.4545118808746338, -1, 193, []], [0.4545259475708008, 1, 0, []], [0.6404750347137451, 1, 425, []], [0.6802589893341064, -1, 502, []], [0.6804039478302002, 1, 424, []], [0.717540979385376, -1, 498, []], [0.7557289600372314, 1, 0, []]]
# 0	192.168.1.104:41852<=>67.205.52.141:80	[[0.28197383880615234, 1, 0, ['SYN']], [0.321760892868042, -1, 0, ['SYN']], [0.32176995277404785, 1, 0, []], [0.32178807258605957, 1, 421, []], [0.36988401412963867, -1, 0, []]]
# 0	192.168.1.104:41853<=>67.205.52.141:80	[[0.2820110321044922, 1, 0, ['SYN']], [0.3218979835510254, -1, 0, ['SYN']], [0.3219120502471924, 1, 0, []], [0.3219430446624756, 1, 420, []], [0.3704500198364258, -1, 0, []]]
# 0	192.168.1.104:41854<=>67.205.52.141:80	[[0.2820320129394531, 1, 0, ['SYN']], [0.320842981338501, -1, 0, ['SYN']], [0.3208749294281006, 1, 0, []], [0.3209249973297119, 1, 421, []], [0.36191606521606445, -1, 0, []], [0.45537900924682617, -1, 1448, []], [0.45539188385009766, 1, 0, []], [0.45665788650512695, -1, 1156, []], [0.45667004585266113, 1, 0, []], [0.640841007232666, 1, 423, []], [0.6794509887695312, -1, 0, []], [0.6820130348205566, -1, 498, []], [0.6820249557495117, 1, 0, []]]
# 0	192.168.1.104:41855<=>67.205.52.141:80	[[0.28205204010009766, 1, 0, ['SYN']], [0.32164692878723145, -1, 0, ['SYN']], [0.32166290283203125, 1, 0, []], [0.3216969966888428, 1, 418, []], [0.37019801139831543, -1, 0, []]]
# 1	67.205.52.141:80<=>192.168.1.104:41855	[[1.4794259071350098, 1, 1448, []], [1.4794559478759766, -1, 0, []], [1.4809470176696777, 1, 1448, []], [1.4809658527374268, -1, 0, []], [1.4821488857269287, 1, 1448, []], [1.4821629524230957, -1, 0, []], [1.518265962600708, 1, 679, []], [1.5182878971099854, -1, 0, []]]
# 1	67.205.52.141:80<=>192.168.1.104:41852	[[1.4836549758911133, 1, 1448, []], [1.4836678504943848, -1, 0, []], [1.485219955444336, 1, 1448, []], [1.485231876373291, -1, 0, []], [1.4869489669799805, 1, 1448, []], [1.4869599342346191, -1, 0, []], [1.5252759456634521, 1, 1448, []], [1.525291919708252, -1, 0, []], [1.5262038707733154, 1, 1448, []], [1.5262150764465332, -1, 0, []], [1.5267419815063477, 1, 1448, []], [1.526749849319458, -1, 0, []], [1.527271032333374, 1, 1448, []], [1.5272810459136963, -1, 0, []], [1.5280609130859375, 1, 1448, []], [1.5280709266662598, -1, 0, []], [1.528756856918335, 1, 1448, []], [1.5287668704986572, -1, 0, []], [1.5697190761566162, 1, 1448, []], [1.5697429180145264, -1, 0, []], [1.570530891418457, 1, 1448, []], [1.5705430507659912, -1, 0, []], [1.5714778900146484, 1, 1448, []], [1.5714879035949707, -1, 0, []], [1.5721728801727295, 1, 906, []], [1.57218599319458, -1, 0, []]]
# 2	67.205.52.141:80<=>192.168.1.104:41853	[[2.460947036743164, 1, 502, []], [2.4609780311584473, -1, 0, []]]
# 2	192.168.1.104:41854<=>67.205.52.141:80	[[2.4715280532836914, 1, 375, []], [2.5091729164123535, -1, 275, []], [2.5091938972473145, 1, 0, []]]
# 2	67.205.52.141:80<=>192.168.1.104:41850	[[2.721740961074829, 1, 0, ['FIN']], [2.7602288722991943, -1, 0, []]]
# 2	67.205.52.141:80<=>192.168.1.104:41849	[[2.722036838531494, 1, 0, ['FIN']], [2.7602388858795166, -1, 0, []]]
# 3	67.205.52.141:80<=>192.168.1.104:41855	[[3.481139898300171, 1, 0, ['FIN']], [3.5209670066833496, -1, 0, []], [3.8310389518737793, -1, 0, ['FIN']], [3.8680100440979004, 1, 0, []]]
# 3	67.205.52.141:80<=>192.168.1.104:41852	[[3.5658349990844727, 1, 0, ['FIN']], [3.6050548553466797, -1, 0, []], [3.8310279846191406, -1, 0, ['FIN']], [3.8676209449768066, 1, 0, []]]
# 3	192.168.1.104:41854<=>67.205.52.141:80	[[3.8310019969940186, 1, 0, ['FIN']], [3.868234872817993, -1, 0, ['FIN']], [3.868245840072632, 1, 0, []]]
# 3	192.168.1.104:41849<=>67.205.52.141:80	[[3.8310508728027344, 1, 0, ['FIN']], [3.867733955383301, -1, 0, []]]
# 3	192.168.1.104:41850<=>67.205.52.141:80	[[3.831061840057373, 1, 0, ['FIN']], [3.867357015609741, -1, 0, []]]
# 3	192.168.1.104:41853<=>67.205.52.141:80	[[3.831073045730591, 1, 0, ['FIN']], [3.8681318759918213, -1, 0, ['FIN']], [3.868144989013672, 1, 0, []]]


# In[37]:


# To calculate the total seconds a flow is idle based on specific flags, you need to analyze the packets in the flow and identify the periods when no packets with those flags are observed. Here's a step-by-step approach:

# Iterate through the packets in each flow.
# Track the timestamps of the last packet that does not have the specific flags (e.g., SYN and FIN) encountered.
# When a packet with the specific flags is encountered, calculate the duration of the idle period by subtracting the timestamp of the last packet without the specific flags from the current packet's timestamp.
# Keep a running total of the idle duration for each flow.
# At the end of the analysis, you will have the total idle duration for each flow.
import sys
import statistics
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
        print("Bucket\tFlow\tTimestamp\tDirection\tData Size\tFlags")

        flow_buckets = {}  # Dictionary to store flow buckets
        total_forward_packets = 0
        total_backward_packets = 0
        total_forward_bytes = 0
        total_backward_bytes = 0

        first_ts = None  # Variable to store the timestamp of the first packet

        for ts, buf in pcap:
            if first_ts is None:
                first_ts = ts  # Set the timestamp of the first captured packet

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

            bucket_index = int((ts - first_ts) // 2)  # Calculate the bucket index

            if bucket_index in flow_buckets:
                if flow in flow_buckets[bucket_index]:
                    flow_buckets[bucket_index][flow].append((ts, buf, tcp.sport, tcp.dport, len(tcp.data), tcp.flags))
                elif reverse_flow in flow_buckets[bucket_index]:
                    flow_buckets[bucket_index][reverse_flow].append((ts, buf, tcp.sport, tcp.dport, len(tcp.data), tcp.flags))
                else:
                    flow_buckets[bucket_index][flow] = [(ts, buf, tcp.sport, tcp.dport, len(tcp.data), tcp.flags)]
            else:
                flow_buckets[bucket_index] = {flow: [(ts, buf, tcp.sport, tcp.dport, len(tcp.data), tcp.flags)]}

        # Process flow buckets
        for bucket_index, flows in flow_buckets.items():
            forward_packets = 0
            backward_packets = 0
            forward_bytes = 0
            backward_bytes = 0
            forward_interarrival_times = []
            backward_interarrival_times = []
            total_flow_interarrival_time = 0

            for flow, packets in flows.items():
                if len(packets) < 20:
                    continue  # Discard the bucket if it has less than 20 packets

                for idx, (ts, buf, src_port, dst_port, data_size, flags) in enumerate(packets):
                    eth = dpkt.ethernet.Ethernet(buf)
                    ip = eth.data
                    tcp = ip.data
                    direction = 1 if connection_id_to_str((ip.src, tcp.sport, ip.dst, tcp.dport)) == flow else -1
                    if direction == 1:
                        forward_packets += 1
                        forward_bytes += data_size
                        forward_interarrival_times.append(ts - first_ts - total_flow_interarrival_time)
                    else:
                        backward_packets += 1
                        backward_bytes += data_size
                        backward_interarrival_times.append(ts - first_ts - total_flow_interarrival_time)

                    if idx == 0:
                        timestamp = ts - first_ts
                    else:
                        timestamp = ts - first_ts 

                    total_flow_interarrival_time = ts - first_ts

                    flag_names = []
                    if flags & dpkt.tcp.TH_SYN:
                        flag_names.append("SYN")
                    if flags & dpkt.tcp.TH_FIN:
                        flag_names.append("FIN")

                    print(f"{bucket_index}\t{flow}\t{timestamp}\t{direction}\t{data_size}\t{flag_names}")

            total_forward_packets += forward_packets
            total_backward_packets += backward_packets
            total_forward_bytes += forward_bytes
            total_backward_bytes += backward_bytes

            backward_interarrival_time = sum(backward_interarrival_times) / backward_packets if backward_packets > 0 else 0
            flow_interarrival_time = total_flow_interarrival_time / (forward_packets + backward_packets) if (forward_packets + backward_packets) > 0 else 0
            forward_interarrival_time = sum(forward_interarrival_times) / forward_packets if forward_packets > 0 else 0

            print(f"Bucket {bucket_index} Summary:")
            print(f"Forward Packets: {forward_packets}")
            print(f"Backward Packets: {backward_packets}")
            print(f"Total Bytes per Second: {total_forward_bytes + total_backward_bytes}")
            print(f"Total Forward Bytes: {total_forward_bytes}")
            print(f"Total Backward Bytes: {total_backward_bytes}")
            print(f"Forward Inter-arrival Time: {forward_interarrival_time}")
            print(f"Backward Inter-arrival Time: {backward_interarrival_time}")
            print(f"Flow Inter-arrival Time: {flow_interarrival_time}")
            print(f"---")

        print("Total Summary:")
        print(f"Total Forward Packets: {total_forward_packets}")
        print(f"Total Backward Packets: {total_backward_packets}")
        print(f"Total Bytes per Second: {total_forward_bytes + total_backward_bytes}")
        print(f"Total Forward Bytes: {total_forward_bytes}")
        print(f"Total Backward Bytes: {total_backward_bytes}")

analyze_pcap_file('E:\PPT Reader\http_ipv4_complex.cap')

# Bucket	Flow	Timestamp	Direction	Data Size	Flags
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.0	1	0	['SYN']
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.052906036376953125	-1	0	['SYN']
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.05294084548950195	1	0	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.052983999252319336	1	394	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.11489295959472656	-1	0	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.11852192878723145	-1	1448	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.11853599548339844	1	0	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.11969304084777832	-1	1448	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.11970996856689453	1	0	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.12064886093139648	-1	1448	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.12066006660461426	1	0	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.15792107582092285	-1	1448	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.15794801712036133	1	0	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.16084790229797363	-1	1448	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.16086697578430176	1	0	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.16356396675109863	-1	1448	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.1635758876800537	1	0	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.16584992408752441	-1	1448	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.16586089134216309	1	0	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.16829490661621094	-1	1448	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.1683049201965332	1	0	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.17022991180419922	-1	1289	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.17024803161621094	1	0	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.20525884628295898	1	452	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.2444610595703125	-1	496	[]
# # 0	192.168.1.104:41849<=>67.205.52.141:80	0.24945998191833496	1	421	[]
# # 0	192.168.1.104:41849<=>67.205.52.141:80	0.28720784187316895	-1	495	[]
# # 0	192.168.1.104:41849<=>67.205.52.141:80	0.2873108386993408	1	425	[]
# # 0	192.168.1.104:41849<=>67.205.52.141:80	0.32711005210876465	-1	502	[]
# # 0	192.168.1.104:41849<=>67.205.52.141:80	0.32723307609558105	1	423	[]
# # 0	192.168.1.104:41849<=>67.205.52.141:80	0.3706519603729248	-1	498	[]
# # 0	192.168.1.104:41849<=>67.205.52.141:80	0.37079286575317383	1	424	[]
# # 0	192.168.1.104:41849<=>67.205.52.141:80	0.4094369411468506	-1	498	[]
# # 0	192.168.1.104:41849<=>67.205.52.141:80	0.4096200466156006	1	419	[]
# # 0	192.168.1.104:41849<=>67.205.52.141:80	0.4471158981323242	-1	495	[]
# # 0	192.168.1.104:41849<=>67.205.52.141:80	0.48822689056396484	1	0	[]
# # 0	192.168.1.104:41849<=>67.205.52.141:80	0.639970064163208	1	421	[]
# # 0	192.168.1.104:41849<=>67.205.52.141:80	0.6809289455413818	-1	495	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.6809430122375488	1	0	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.6810150146484375	1	419	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.7179288864135742	-1	495	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.7597248554229736	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.20777392387390137	1	0	['SYN']
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.249237060546875	-1	0	['SYN']
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.24925684928894043	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.24938392639160156	1	426	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.28623104095458984	-1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3043830394744873	-1	1448	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.30440306663513184	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3060338497161865	-1	1448	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3060438632965088	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3069939613342285	-1	1448	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3070030212402344	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3428220748901367	-1	1448	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.34283900260925293	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.34386301040649414	-1	1448	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.34387993812561035	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.346904993057251	-1	1448	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.34691691398620605	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.34802889823913574	-1	1448	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3480379581451416	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3494069576263428	-1	1448	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.34941697120666504	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.35040783882141113	-1	1448	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3504209518432617	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.38700103759765625	-1	1448	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3870229721069336	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3917560577392578	-1	1448	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.39177894592285156	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3948628902435303	-1	1448	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.39487695693969727	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3967628479003906	-1	176	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3967759609222412	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.396867036819458	1	415	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.4540748596191406	-1	1448	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.4545118808746338	-1	193	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.4545259475708008	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.6404750347137451	1	425	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.6802589893341064	-1	502	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.6804039478302002	1	424	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.717540979385376	-1	498	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.7557289600372314	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	0.28197383880615234	1	0	['SYN']
# 0	192.168.1.104:41852<=>67.205.52.141:80	0.321760892868042	-1	0	['SYN']
# 0	192.168.1.104:41852<=>67.205.52.141:80	0.32176995277404785	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	0.32178807258605957	1	421	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	0.36988401412963867	-1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.4836549758911133	-1	1448	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.4836678504943848	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.485219955444336	-1	1448	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.485231876373291	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.4869489669799805	-1	1448	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.4869599342346191	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5252759456634521	-1	1448	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.525291919708252	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5262038707733154	-1	1448	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5262150764465332	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5267419815063477	-1	1448	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.526749849319458	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.527271032333374	-1	1448	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5272810459136963	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5280609130859375	-1	1448	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5280709266662598	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.528756856918335	-1	1448	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5287668704986572	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5697190761566162	-1	1448	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5697429180145264	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.570530891418457	-1	1448	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5705430507659912	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5714778900146484	-1	1448	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5714879035949707	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5721728801727295	-1	906	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.57218599319458	1	0	[]
# Bucket 0 Summary:
# Forward Packets: 60
# Backward Packets: 53
# Total Bytes per Second: 61231
# Total Forward Bytes: 5909
# Total Backward Bytes: 55322
# Forward Inter-arrival Time: -0.00875471035639445
# Backward Inter-arrival Time: 0.03957487952034428
# Flow Inter-arrival Time: 0.013913150382252921
# ---
# Bucket 1 Summary:
# Forward Packets: 0
# Backward Packets: 0
# Total Bytes per Second: 61231
# Total Forward Bytes: 5909
# Total Backward Bytes: 55322
# Forward Inter-arrival Time: 0
# Backward Inter-arrival Time: 0
# Flow Inter-arrival Time: 0
# ---
# Total Summary:
# Total Forward Packets: 60
# Total Backward Packets: 53
# Total Bytes per Second: 61231
# Total Forward Bytes: 5909
# Total Backward Bytes: 55322


# In[ ]:


# To calculate the total seconds a flow is idle based on specific flags, you need to analyze the packets in the flow and identify the periods when no packets with those flags are observed. Here's a step-by-step approach:

# Iterate through the packets in each flow.
# Track the timestamps of the last packet that does not have the specific flags (e.g., SYN and FIN) encountered.
# When a packet with the specific flags is encountered, calculate the duration of the idle period by subtracting the timestamp of the last packet without the specific flags from the current packet's timestamp.
# Keep a running total of the idle duration for each flow.
# At the end of the analysis, you will have the total idle duration for each flow.
# if a flow encounters only the SYN flag without the FIN flag, the active and idle times for that flow cannot be determined accurately because the FIN flag indicates the end of a flow.

# When a flow encounters only the SYN flag and no subsequent FIN flag, it means the flow is still active and ongoing. In this case, the active time cannot be calculated because the flow is not complete.

# As for the idle time, the code considers the idle time as the duration between packets that have specific flags (SYN and FIN) and packets that do not have those flags within the same flow. Since there is no FIN flag observed in this scenario, the idle time for the flow cannot be accurately determined.


# In[40]:


def analyze_pcap_file(file_path):
    """This function analyzes a pcap file and prints flow information"""
    with open(file_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        print("Bucket\tFlow\tTimestamp\tDirection\tData Size\tFlags")

        flow_buckets = {}  # Dictionary to store flow buckets
        total_forward_packets = 0
        total_backward_packets = 0
        total_forward_bytes = 0
        total_backward_bytes = 0
        active_time = {}  # Dictionary to store active time for each flow
        idle_time = {}  # Dictionary to store idle time for each flow

        first_ts = None  # Variable to store the timestamp of the first packet

        for ts, buf in pcap:
            if first_ts is None:
                first_ts = ts  # Set the timestamp of the first captured packet

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

            bucket_index = int((ts - first_ts) // 2)  # Calculate the bucket index

            if bucket_index in flow_buckets:
                if flow in flow_buckets[bucket_index]:
                    flow_buckets[bucket_index][flow].append((ts, buf, tcp.sport, tcp.dport, len(tcp.data), tcp.flags))
                elif reverse_flow in flow_buckets[bucket_index]:
                    flow_buckets[bucket_index][reverse_flow].append((ts, buf, tcp.sport, tcp.dport, len(tcp.data), tcp.flags))
                else:
                    flow_buckets[bucket_index][flow] = [(ts, buf, tcp.sport, tcp.dport, len(tcp.data), tcp.flags)]
            else:
                flow_buckets[bucket_index] = {flow: [(ts, buf, tcp.sport, tcp.dport, len(tcp.data), tcp.flags)]}

        # Process flow buckets
        for bucket_index, flows in flow_buckets.items():
            forward_packets = 0
            backward_packets = 0
            forward_bytes = 0
            backward_bytes = 0
            forward_interarrival_times = []
            backward_interarrival_times = []
            total_flow_interarrival_time = 0

            for flow, packets in flows.items():
                if len(packets) < 20:
                    continue  # Discard the bucket if it has less than 20 packets

                active_start_time = None  # Track the start time of active period
                last_idle_packet_ts = None  # Track the timestamp of the last packet without SYN or FIN flags

                for idx, (ts, buf, src_port, dst_port, data_size, flags) in enumerate(packets):
                    eth = dpkt.ethernet.Ethernet(buf)
                    ip = eth.data
                    tcp = ip.data
                    direction = 1 if connection_id_to_str((ip.src, tcp.sport, ip.dst, tcp.dport)) == flow else -1
                    if direction == 1:
                        forward_packets += 1
                        forward_bytes += data_size
                        forward_interarrival_times.append(ts - first_ts - total_flow_interarrival_time)
                    else:
                        backward_packets += 1
                        backward_bytes += data_size
                        backward_interarrival_times.append(ts - first_ts - total_flow_interarrival_time)

                    if idx == 0:
                        timestamp = ts - first_ts
                    else:
                        timestamp = ts - first_ts

                    total_flow_interarrival_time = ts - first_ts

                    flag_names = []
                    if flags & dpkt.tcp.TH_SYN:
                        flag_names.append("SYN")
                    if flags & dpkt.tcp.TH_FIN:
                        flag_names.append("FIN")

                    print(f"{bucket_index}\t{flow}\t{timestamp}\t{direction}\t{data_size}\t{flag_names}")

                    # Calculate active and idle time
                    if "SYN" in flag_names or "FIN" in flag_names:
                        if active_start_time is not None:
                            # Calculate the duration of the previous active period
                            active_duration = ts - active_start_time
                            if flow in active_time:
                                active_time[flow] += active_duration
                            else:
                                active_time[flow] = active_duration

                            active_start_time = None

                        last_idle_packet_ts = None
                    else:
                        if active_start_time is None:
                            active_start_time = ts
                        last_idle_packet_ts = ts

                # Check if the flow ends with an active period
                if active_start_time is not None:
                    # Calculate the duration of the last active period
                    active_duration = total_flow_interarrival_time - active_start_time
                    if flow in active_time:
                        active_time[flow] += active_duration
                    else:
                        active_time[flow] = active_duration

                # Check if the flow ends with an idle period
                if last_idle_packet_ts is not None:
                    # Calculate the duration of the last idle period
                    idle_duration = total_flow_interarrival_time - last_idle_packet_ts
                    if flow in idle_time:
                        idle_time[flow] += idle_duration
                    else:
                        idle_time[flow] = idle_duration

            total_forward_packets += forward_packets
            total_backward_packets += backward_packets
            total_forward_bytes += forward_bytes
            total_backward_bytes += backward_bytes

            backward_interarrival_time = (
                sum(backward_interarrival_times) / backward_packets if backward_packets > 0 else 0
            )
            flow_interarrival_time = (
                total_flow_interarrival_time / (forward_packets + backward_packets)
                if (forward_packets + backward_packets) > 0
                else 0
            )
            forward_interarrival_time = (
                sum(forward_interarrival_times) / forward_packets if forward_packets > 0 else 0
            )

            print(f"Bucket {bucket_index} Summary:")
            print(f"Forward Packets: {forward_packets}")
            print(f"Backward Packets: {backward_packets}")
            print(f"Total Bytes per Second: {total_forward_bytes + total_backward_bytes}")
            print(f"Total Forward Bytes: {total_forward_bytes}")
            print(f"Total Backward Bytes: {total_backward_bytes}")
            print(f"Forward Inter-arrival Time: {forward_interarrival_time}")
            print(f"Backward Inter-arrival Time: {backward_interarrival_time}")
            print(f"Flow Inter-arrival Time: {flow_interarrival_time}")
            print(f"---")

        print("Total Summary:")
        print(f"Total Forward Packets: {total_forward_packets}")
        print(f"Total Backward Packets: {total_backward_packets}")
        print(f"Total Bytes per Second: {total_forward_bytes + total_backward_bytes}")
        print(f"Total Forward Bytes: {total_forward_bytes}")
        print(f"Total Backward Bytes: {total_backward_bytes}")

        print("\nIdle Time:")
        for flow, duration in idle_time.items():
            print(f"Flow: {flow}\tIdle Time: {duration} seconds")

        print("\nActive Time:")
        for flow, duration in active_time.items():
            print(f"Flow: {flow}\tActive Time: {duration} seconds")
         
        print("\nIdle Time:")
        for flow, duration in idle_time.items():
            print(f"Flow: {flow}\tIdle Time: {duration} seconds")

        print("\nActive Time:")
        for flow, duration in active_time.items():
            print(f"Flow: {flow}\tActive Time: {duration} seconds")

        # Print Flow Information
        print("\nFlow Information:")
        for bucket_index, flows in flow_buckets.items():
            for flow, packets in flows.items():
                print(f"Flow: {flow}")
                print("Packet Information:")
                for idx, (ts, buf, src_port, dst_port, data_size, flags) in enumerate(packets):
                    eth = dpkt.ethernet.Ethernet(buf)
                    ip = eth.data
                    tcp = ip.data
                    direction = 1 if connection_id_to_str((ip.src, tcp.sport, ip.dst, tcp.dport)) == flow else -1
                    flag_names = []
                    if flags & dpkt.tcp.TH_SYN:
                        flag_names.append("SYN")
                    if flags & dpkt.tcp.TH_FIN:
                        flag_names.append("FIN")
                    print(f"Packet {idx+1} - Timestamp: {ts - first_ts}\tDirection: {direction}\tData Size: {data_size}\tFlags: {flag_names}")
                print("---")


analyze_pcap_file('E:\PPT Reader\http_ipv4_complex.cap')

# Bucket	Flow	Timestamp	Direction	Data Size	Flags
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.0	1	0	['SYN']
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.052906036376953125	-1	0	['SYN']
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.05294084548950195	1	0	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.052983999252319336	1	394	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.11489295959472656	-1	0	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.11852192878723145	-1	1448	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.11853599548339844	1	0	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.11969304084777832	-1	1448	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.11970996856689453	1	0	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.12064886093139648	-1	1448	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.12066006660461426	1	0	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.15792107582092285	-1	1448	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.15794801712036133	1	0	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.16084790229797363	-1	1448	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.16086697578430176	1	0	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.16356396675109863	-1	1448	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.1635758876800537	1	0	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.16584992408752441	-1	1448	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.16586089134216309	1	0	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.16829490661621094	-1	1448	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.1683049201965332	1	0	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.17022991180419922	-1	1289	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.17024803161621094	1	0	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.20525884628295898	1	452	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.2444610595703125	-1	496	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.24945998191833496	1	421	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.28720784187316895	-1	495	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.2873108386993408	1	425	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.32711005210876465	-1	502	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.32723307609558105	1	423	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.3706519603729248	-1	498	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.37079286575317383	1	424	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.4094369411468506	-1	498	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.4096200466156006	1	419	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.4471158981323242	-1	495	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.48822689056396484	1	0	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.639970064163208	1	421	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.6809289455413818	-1	495	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.6809430122375488	1	0	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.6810150146484375	1	419	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.7179288864135742	-1	495	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.7597248554229736	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.20777392387390137	1	0	['SYN']
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.249237060546875	-1	0	['SYN']
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.24925684928894043	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.24938392639160156	1	426	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.28623104095458984	-1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3043830394744873	-1	1448	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.30440306663513184	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3060338497161865	-1	1448	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3060438632965088	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3069939613342285	-1	1448	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3070030212402344	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3428220748901367	-1	1448	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.34283900260925293	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.34386301040649414	-1	1448	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.34387993812561035	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.346904993057251	-1	1448	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.34691691398620605	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.34802889823913574	-1	1448	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3480379581451416	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3494069576263428	-1	1448	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.34941697120666504	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.35040783882141113	-1	1448	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3504209518432617	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.38700103759765625	-1	1448	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3870229721069336	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3917560577392578	-1	1448	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.39177894592285156	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3948628902435303	-1	1448	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.39487695693969727	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3967628479003906	-1	176	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3967759609222412	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.396867036819458	1	415	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.4540748596191406	-1	1448	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.4545118808746338	-1	193	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.4545259475708008	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.6404750347137451	1	425	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.6802589893341064	-1	502	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.6804039478302002	1	424	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.717540979385376	-1	498	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.7557289600372314	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	0.28197383880615234	1	0	['SYN']
# 0	192.168.1.104:41852<=>67.205.52.141:80	0.321760892868042	-1	0	['SYN']
# 0	192.168.1.104:41852<=>67.205.52.141:80	0.32176995277404785	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	0.32178807258605957	1	421	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	0.36988401412963867	-1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.4836549758911133	-1	1448	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.4836678504943848	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.485219955444336	-1	1448	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.485231876373291	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.4869489669799805	-1	1448	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.4869599342346191	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5252759456634521	-1	1448	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.525291919708252	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5262038707733154	-1	1448	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5262150764465332	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5267419815063477	-1	1448	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.526749849319458	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.527271032333374	-1	1448	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5272810459136963	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5280609130859375	-1	1448	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5280709266662598	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.528756856918335	-1	1448	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5287668704986572	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5697190761566162	-1	1448	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5697429180145264	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.570530891418457	-1	1448	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5705430507659912	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5714778900146484	-1	1448	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5714879035949707	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5721728801727295	-1	906	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.57218599319458	1	0	[]
# Bucket 0 Summary:
# Forward Packets: 60
# Backward Packets: 53
# Total Bytes per Second: 61231
# Total Forward Bytes: 5909
# Total Backward Bytes: 55322
# Forward Inter-arrival Time: -0.00875471035639445
# Backward Inter-arrival Time: 0.03957487952034428
# Flow Inter-arrival Time: 0.013913150382252921
# ---
# Bucket 1 Summary:
# Forward Packets: 0
# Backward Packets: 0
# Total Bytes per Second: 61231
# Total Forward Bytes: 5909
# Total Backward Bytes: 55322
# Forward Inter-arrival Time: 0
# Backward Inter-arrival Time: 0
# Flow Inter-arrival Time: 0
# ---
# Total Summary:
# Total Forward Packets: 60
# Total Backward Packets: 53
# Total Bytes per Second: 61231
# Total Forward Bytes: 5909
# Total Backward Bytes: 55322

# Idle Time:
# Flow: 192.168.1.104:41849<=>67.205.52.141:80	Idle Time: -1302495279.353332 seconds
# Flow: 192.168.1.104:41850<=>67.205.52.141:80	Idle Time: -1302495279.353332 seconds
# Flow: 192.168.1.104:41852<=>67.205.52.141:80	Idle Time: -1302495279.353332 seconds

# Active Time:
# Flow: 192.168.1.104:41849<=>67.205.52.141:80	Active Time: -1302495278.646548 seconds
# Flow: 192.168.1.104:41850<=>67.205.52.141:80	Active Time: -1302495278.84686 seconds
# Flow: 192.168.1.104:41852<=>67.205.52.141:80	Active Time: -1302495278.102916 seconds

# Idle Time:
# Flow: 192.168.1.104:41849<=>67.205.52.141:80	Idle Time: -1302495279.353332 seconds
# Flow: 192.168.1.104:41850<=>67.205.52.141:80	Idle Time: -1302495279.353332 seconds
# Flow: 192.168.1.104:41852<=>67.205.52.141:80	Idle Time: -1302495279.353332 seconds

# Active Time:
# Flow: 192.168.1.104:41849<=>67.205.52.141:80	Active Time: -1302495278.646548 seconds
# Flow: 192.168.1.104:41850<=>67.205.52.141:80	Active Time: -1302495278.84686 seconds
# Flow: 192.168.1.104:41852<=>67.205.52.141:80	Active Time: -1302495278.102916 seconds

# Flow Information:
# Flow: 192.168.1.104:41849<=>67.205.52.141:80
# Packet Information:
# Packet 1 - Timestamp: 0.0	Direction: 1	Data Size: 0	Flags: ['SYN']
# Packet 2 - Timestamp: 0.052906036376953125	Direction: -1	Data Size: 0	Flags: ['SYN']
# Packet 3 - Timestamp: 0.05294084548950195	Direction: 1	Data Size: 0	Flags: []
# Packet 4 - Timestamp: 0.052983999252319336	Direction: 1	Data Size: 394	Flags: []
# Packet 5 - Timestamp: 0.11489295959472656	Direction: -1	Data Size: 0	Flags: []
# Packet 6 - Timestamp: 0.11852192878723145	Direction: -1	Data Size: 1448	Flags: []
# Packet 7 - Timestamp: 0.11853599548339844	Direction: 1	Data Size: 0	Flags: []
# Packet 8 - Timestamp: 0.11969304084777832	Direction: -1	Data Size: 1448	Flags: []
# Packet 9 - Timestamp: 0.11970996856689453	Direction: 1	Data Size: 0	Flags: []
# Packet 10 - Timestamp: 0.12064886093139648	Direction: -1	Data Size: 1448	Flags: []
# Packet 11 - Timestamp: 0.12066006660461426	Direction: 1	Data Size: 0	Flags: []
# Packet 12 - Timestamp: 0.15792107582092285	Direction: -1	Data Size: 1448	Flags: []
# Packet 13 - Timestamp: 0.15794801712036133	Direction: 1	Data Size: 0	Flags: []
# Packet 14 - Timestamp: 0.16084790229797363	Direction: -1	Data Size: 1448	Flags: []
# Packet 15 - Timestamp: 0.16086697578430176	Direction: 1	Data Size: 0	Flags: []
# Packet 16 - Timestamp: 0.16356396675109863	Direction: -1	Data Size: 1448	Flags: []
# Packet 17 - Timestamp: 0.1635758876800537	Direction: 1	Data Size: 0	Flags: []
# Packet 18 - Timestamp: 0.16584992408752441	Direction: -1	Data Size: 1448	Flags: []
# Packet 19 - Timestamp: 0.16586089134216309	Direction: 1	Data Size: 0	Flags: []
# Packet 20 - Timestamp: 0.16829490661621094	Direction: -1	Data Size: 1448	Flags: []
# Packet 21 - Timestamp: 0.1683049201965332	Direction: 1	Data Size: 0	Flags: []
# Packet 22 - Timestamp: 0.17022991180419922	Direction: -1	Data Size: 1289	Flags: []
# Packet 23 - Timestamp: 0.17024803161621094	Direction: 1	Data Size: 0	Flags: []
# Packet 24 - Timestamp: 0.20525884628295898	Direction: 1	Data Size: 452	Flags: []
# Packet 25 - Timestamp: 0.2444610595703125	Direction: -1	Data Size: 496	Flags: []
# Packet 26 - Timestamp: 0.24945998191833496	Direction: 1	Data Size: 421	Flags: []
# Packet 27 - Timestamp: 0.28720784187316895	Direction: -1	Data Size: 495	Flags: []
# Packet 28 - Timestamp: 0.2873108386993408	Direction: 1	Data Size: 425	Flags: []
# Packet 29 - Timestamp: 0.32711005210876465	Direction: -1	Data Size: 502	Flags: []
# Packet 30 - Timestamp: 0.32723307609558105	Direction: 1	Data Size: 423	Flags: []
# Packet 31 - Timestamp: 0.3706519603729248	Direction: -1	Data Size: 498	Flags: []
# Packet 32 - Timestamp: 0.37079286575317383	Direction: 1	Data Size: 424	Flags: []
# Packet 33 - Timestamp: 0.4094369411468506	Direction: -1	Data Size: 498	Flags: []
# Packet 34 - Timestamp: 0.4096200466156006	Direction: 1	Data Size: 419	Flags: []
# Packet 35 - Timestamp: 0.4471158981323242	Direction: -1	Data Size: 495	Flags: []
# Packet 36 - Timestamp: 0.48822689056396484	Direction: 1	Data Size: 0	Flags: []
# Packet 37 - Timestamp: 0.639970064163208	Direction: 1	Data Size: 421	Flags: []
# Packet 38 - Timestamp: 0.6809289455413818	Direction: -1	Data Size: 495	Flags: []
# Packet 39 - Timestamp: 0.6809430122375488	Direction: 1	Data Size: 0	Flags: []
# Packet 40 - Timestamp: 0.6810150146484375	Direction: 1	Data Size: 419	Flags: []
# Packet 41 - Timestamp: 0.7179288864135742	Direction: -1	Data Size: 495	Flags: []
# Packet 42 - Timestamp: 0.7597248554229736	Direction: 1	Data Size: 0	Flags: []
# ---
# Flow: 192.168.1.104:41850<=>67.205.52.141:80
# Packet Information:
# Packet 1 - Timestamp: 0.20777392387390137	Direction: 1	Data Size: 0	Flags: ['SYN']
# Packet 2 - Timestamp: 0.249237060546875	Direction: -1	Data Size: 0	Flags: ['SYN']
# Packet 3 - Timestamp: 0.24925684928894043	Direction: 1	Data Size: 0	Flags: []
# Packet 4 - Timestamp: 0.24938392639160156	Direction: 1	Data Size: 426	Flags: []
# Packet 5 - Timestamp: 0.28623104095458984	Direction: -1	Data Size: 0	Flags: []
# Packet 6 - Timestamp: 0.3043830394744873	Direction: -1	Data Size: 1448	Flags: []
# Packet 7 - Timestamp: 0.30440306663513184	Direction: 1	Data Size: 0	Flags: []
# Packet 8 - Timestamp: 0.3060338497161865	Direction: -1	Data Size: 1448	Flags: []
# Packet 9 - Timestamp: 0.3060438632965088	Direction: 1	Data Size: 0	Flags: []
# Packet 10 - Timestamp: 0.3069939613342285	Direction: -1	Data Size: 1448	Flags: []
# Packet 11 - Timestamp: 0.3070030212402344	Direction: 1	Data Size: 0	Flags: []
# Packet 12 - Timestamp: 0.3428220748901367	Direction: -1	Data Size: 1448	Flags: []
# Packet 13 - Timestamp: 0.34283900260925293	Direction: 1	Data Size: 0	Flags: []
# Packet 14 - Timestamp: 0.34386301040649414	Direction: -1	Data Size: 1448	Flags: []
# Packet 15 - Timestamp: 0.34387993812561035	Direction: 1	Data Size: 0	Flags: []
# Packet 16 - Timestamp: 0.346904993057251	Direction: -1	Data Size: 1448	Flags: []
# Packet 17 - Timestamp: 0.34691691398620605	Direction: 1	Data Size: 0	Flags: []
# Packet 18 - Timestamp: 0.34802889823913574	Direction: -1	Data Size: 1448	Flags: []
# Packet 19 - Timestamp: 0.3480379581451416	Direction: 1	Data Size: 0	Flags: []
# Packet 20 - Timestamp: 0.3494069576263428	Direction: -1	Data Size: 1448	Flags: []
# Packet 21 - Timestamp: 0.34941697120666504	Direction: 1	Data Size: 0	Flags: []
# Packet 22 - Timestamp: 0.35040783882141113	Direction: -1	Data Size: 1448	Flags: []
# Packet 23 - Timestamp: 0.3504209518432617	Direction: 1	Data Size: 0	Flags: []
# Packet 24 - Timestamp: 0.38700103759765625	Direction: -1	Data Size: 1448	Flags: []
# Packet 25 - Timestamp: 0.3870229721069336	Direction: 1	Data Size: 0	Flags: []
# # Packet 26 - Timestamp: 0.3917560577392578	Direction: -1	Data Size: 1448	Flags: []
# Packet 27 - Timestamp: 0.39177894592285156	Direction: 1	Data Size: 0	Flags: []
# Packet 28 - Timestamp: 0.3948628902435303	Direction: -1	Data Size: 1448	Flags: []
# Packet 29 - Timestamp: 0.39487695693969727	Direction: 1	Data Size: 0	Flags: []
# Packet 30 - Timestamp: 0.3967628479003906	Direction: -1	Data Size: 176	Flags: []
# Packet 31 - Timestamp: 0.3967759609222412	Direction: 1	Data Size: 0	Flags: []
# Packet 32 - Timestamp: 0.396867036819458	Direction: 1	Data Size: 415	Flags: []
# Packet 33 - Timestamp: 0.4540748596191406	Direction: -1	Data Size: 1448	Flags: []
# Packet 34 - Timestamp: 0.4545118808746338	Direction: -1	Data Size: 193	Flags: []
# Packet 35 - Timestamp: 0.4545259475708008	Direction: 1	Data Size: 0	Flags: []
# Packet 36 - Timestamp: 0.6404750347137451	Direction: 1	Data Size: 425	Flags: []
# Packet 37 - Timestamp: 0.6802589893341064	Direction: -1	Data Size: 502	Flags: []
# Packet 38 - Timestamp: 0.6804039478302002	Direction: 1	Data Size: 424	Flags: []
# Packet 39 - Timestamp: 0.717540979385376	Direction: -1	Data Size: 498	Flags: []
# Packet 40 - Timestamp: 0.7557289600372314	Direction: 1	Data Size: 0	Flags: []
# ---
# Flow: 192.168.1.104:41852<=>67.205.52.141:80
# Packet Information:
# Packet 1 - Timestamp: 0.28197383880615234	Direction: 1	Data Size: 0	Flags: ['SYN']
# Packet 2 - Timestamp: 0.321760892868042	Direction: -1	Data Size: 0	Flags: ['SYN']
# Packet 3 - Timestamp: 0.32176995277404785	Direction: 1	Data Size: 0	Flags: []
# Packet 4 - Timestamp: 0.32178807258605957	Direction: 1	Data Size: 421	Flags: []
# Packet 5 - Timestamp: 0.36988401412963867	Direction: -1	Data Size: 0	Flags: []
# Packet 6 - Timestamp: 1.4836549758911133	Direction: -1	Data Size: 1448	Flags: []
# Packet 7 - Timestamp: 1.4836678504943848	Direction: 1	Data Size: 0	Flags: []
# Packet 8 - Timestamp: 1.485219955444336	Direction: -1	Data Size: 1448	Flags: []
# Packet 9 - Timestamp: 1.485231876373291	Direction: 1	Data Size: 0	Flags: []
# Packet 10 - Timestamp: 1.4869489669799805	Direction: -1	Data Size: 1448	Flags: []
# Packet 11 - Timestamp: 1.4869599342346191	Direction: 1	Data Size: 0	Flags: []
# Packet 12 - Timestamp: 1.5252759456634521	Direction: -1	Data Size: 1448	Flags: []
# Packet 13 - Timestamp: 1.525291919708252	Direction: 1	Data Size: 0	Flags: []
# Packet 14 - Timestamp: 1.5262038707733154	Direction: -1	Data Size: 1448	Flags: []
# Packet 15 - Timestamp: 1.5262150764465332	Direction: 1	Data Size: 0	Flags: []
# Packet 16 - Timestamp: 1.5267419815063477	Direction: -1	Data Size: 1448	Flags: []
# Packet 17 - Timestamp: 1.526749849319458	Direction: 1	Data Size: 0	Flags: []
# Packet 18 - Timestamp: 1.527271032333374	Direction: -1	Data Size: 1448	Flags: []
# Packet 19 - Timestamp: 1.5272810459136963	Direction: 1	Data Size: 0	Flags: []
# Packet 20 - Timestamp: 1.5280609130859375	Direction: -1	Data Size: 1448	Flags: []
# Packet 21 - Timestamp: 1.5280709266662598	Direction: 1	Data Size: 0	Flags: []
# Packet 22 - Timestamp: 1.528756856918335	Direction: -1	Data Size: 1448	Flags: []
# Packet 23 - Timestamp: 1.5287668704986572	Direction: 1	Data Size: 0	Flags: []
# Packet 24 - Timestamp: 1.5697190761566162	Direction: -1	Data Size: 1448	Flags: []
# Packet 25 - Timestamp: 1.5697429180145264	Direction: 1	Data Size: 0	Flags: []
# Packet 26 - Timestamp: 1.570530891418457	Direction: -1	Data Size: 1448	Flags: []
# Packet 27 - Timestamp: 1.5705430507659912	Direction: 1	Data Size: 0	Flags: []
# Packet 28 - Timestamp: 1.5714778900146484	Direction: -1	Data Size: 1448	Flags: []
# Packet 29 - Timestamp: 1.5714879035949707	Direction: 1	Data Size: 0	Flags: []
# Packet 30 - Timestamp: 1.5721728801727295	Direction: -1	Data Size: 906	Flags: []
# Packet 31 - Timestamp: 1.57218599319458	Direction: 1	Data Size: 0	Flags: []
# ---
# Flow: 192.168.1.104:41853<=>67.205.52.141:80
# Packet Information:
# Packet 1 - Timestamp: 0.2820110321044922	Direction: 1	Data Size: 0	Flags: ['SYN']
# Packet 2 - Timestamp: 0.3218979835510254	Direction: -1	Data Size: 0	Flags: ['SYN']
# Packet 3 - Timestamp: 0.3219120502471924	Direction: 1	Data Size: 0	Flags: []
# Packet 4 - Timestamp: 0.3219430446624756	Direction: 1	Data Size: 420	Flags: []
# Packet 5 - Timestamp: 0.3704500198364258	Direction: -1	Data Size: 0	Flags: []
# ---
# Flow: 192.168.1.104:41854<=>67.205.52.141:80
# Packet Information:
# Packet 1 - Timestamp: 0.2820320129394531	Direction: 1	Data Size: 0	Flags: ['SYN']
# Packet 2 - Timestamp: 0.320842981338501	Direction: -1	Data Size: 0	Flags: ['SYN']
# Packet 3 - Timestamp: 0.3208749294281006	Direction: 1	Data Size: 0	Flags: []
# Packet 4 - Timestamp: 0.3209249973297119	Direction: 1	Data Size: 421	Flags: []
# Packet 5 - Timestamp: 0.36191606521606445	Direction: -1	Data Size: 0	Flags: []
# Packet 6 - Timestamp: 0.45537900924682617	Direction: -1	Data Size: 1448	Flags: []
# Packet 7 - Timestamp: 0.45539188385009766	Direction: 1	Data Size: 0	Flags: []
# Packet 8 - Timestamp: 0.45665788650512695	Direction: -1	Data Size: 1156	Flags: []
# Packet 9 - Timestamp: 0.45667004585266113	Direction: 1	Data Size: 0	Flags: []
# Packet 10 - Timestamp: 0.640841007232666	Direction: 1	Data Size: 423	Flags: []
# Packet 11 - Timestamp: 0.6794509887695312	Direction: -1	Data Size: 0	Flags: []
# Packet 12 - Timestamp: 0.6820130348205566	Direction: -1	Data Size: 498	Flags: []
# Packet 13 - Timestamp: 0.6820249557495117	Direction: 1	Data Size: 0	Flags: []
# ---
# Flow: 192.168.1.104:41855<=>67.205.52.141:80
# Packet Information:
# Packet 1 - Timestamp: 0.28205204010009766	Direction: 1	Data Size: 0	Flags: ['SYN']
# Packet 2 - Timestamp: 0.32164692878723145	Direction: -1	Data Size: 0	Flags: ['SYN']
# Packet 3 - Timestamp: 0.32166290283203125	Direction: 1	Data Size: 0	Flags: []
# Packet 4 - Timestamp: 0.3216969966888428	Direction: 1	Data Size: 418	Flags: []
# Packet 5 - Timestamp: 0.37019801139831543	Direction: -1	Data Size: 0	Flags: []
# Packet 6 - Timestamp: 1.4794259071350098	Direction: -1	Data Size: 1448	Flags: []
# Packet 7 - Timestamp: 1.4794559478759766	Direction: 1	Data Size: 0	Flags: []
# Packet 8 - Timestamp: 1.4809470176696777	Direction: -1	Data Size: 1448	Flags: []
# Packet 9 - Timestamp: 1.4809658527374268	Direction: 1	Data Size: 0	Flags: []
# Packet 10 - Timestamp: 1.4821488857269287	Direction: -1	Data Size: 1448	Flags: []
# Packet 11 - Timestamp: 1.4821629524230957	Direction: 1	Data Size: 0	Flags: []
# Packet 12 - Timestamp: 1.518265962600708	Direction: -1	Data Size: 679	Flags: []
# Packet 13 - Timestamp: 1.5182878971099854	Direction: 1	Data Size: 0	Flags: []
# ---
# Flow: 67.205.52.141:80<=>192.168.1.104:41853
# Packet Information:
# Packet 1 - Timestamp: 2.460947036743164	Direction: 1	Data Size: 502	Flags: []
# Packet 2 - Timestamp: 2.4609780311584473	Direction: -1	Data Size: 0	Flags: []
# Packet 3 - Timestamp: 3.831073045730591	Direction: -1	Data Size: 0	Flags: ['FIN']
# Packet 4 - Timestamp: 3.8681318759918213	Direction: 1	Data Size: 0	Flags: ['FIN']
# Packet 5 - Timestamp: 3.868144989013672	Direction: -1	Data Size: 0	Flags: []
# ---
# Flow: 192.168.1.104:41854<=>67.205.52.141:80
# Packet Information:
# Packet 1 - Timestamp: 2.4715280532836914	Direction: 1	Data Size: 375	Flags: []
# Packet 2 - Timestamp: 2.5091729164123535	Direction: -1	Data Size: 275	Flags: []
# Packet 3 - Timestamp: 2.5091938972473145	Direction: 1	Data Size: 0	Flags: []
# Packet 4 - Timestamp: 3.8310019969940186	Direction: 1	Data Size: 0	Flags: ['FIN']
# Packet 5 - Timestamp: 3.868234872817993	Direction: -1	Data Size: 0	Flags: ['FIN']
# Packet 6 - Timestamp: 3.868245840072632	Direction: 1	Data Size: 0	Flags: []
# ---
# Flow: 67.205.52.141:80<=>192.168.1.104:41850
# Packet Information:
# Packet 1 - Timestamp: 2.721740961074829	Direction: 1	Data Size: 0	Flags: ['FIN']
# Packet 2 - Timestamp: 2.7602288722991943	Direction: -1	Data Size: 0	Flags: []
# Packet 3 - Timestamp: 3.831061840057373	Direction: -1	Data Size: 0	Flags: ['FIN']
# Packet 4 - Timestamp: 3.867357015609741	Direction: 1	Data Size: 0	Flags: []
# ---
# Flow: 67.205.52.141:80<=>192.168.1.104:41849
# Packet Information:
# Packet 1 - Timestamp: 2.722036838531494	Direction: 1	Data Size: 0	Flags: ['FIN']
# Packet 2 - Timestamp: 2.7602388858795166	Direction: -1	Data Size: 0	Flags: []
# Packet 3 - Timestamp: 3.8310508728027344	Direction: -1	Data Size: 0	Flags: ['FIN']
# Packet 4 - Timestamp: 3.867733955383301	Direction: 1	Data Size: 0	Flags: []
# ---
# Flow: 67.205.52.141:80<=>192.168.1.104:41855
# Packet Information:
# Packet 1 - Timestamp: 3.481139898300171	Direction: 1	Data Size: 0	Flags: ['FIN']
# Packet 2 - Timestamp: 3.5209670066833496	Direction: -1	Data Size: 0	Flags: []
# Packet 3 - Timestamp: 3.8310389518737793	Direction: -1	Data Size: 0	Flags: ['FIN']
# Packet 4 - Timestamp: 3.8680100440979004	Direction: 1	Data Size: 0	Flags: []
# ---
# Flow: 67.205.52.141:80<=>192.168.1.104:41852
# Packet Information:
# Packet 1 - Timestamp: 3.5658349990844727	Direction: 1	Data Size: 0	Flags: ['FIN']
# Packet 2 - Timestamp: 3.6050548553466797	Direction: -1	Data Size: 0	Flags: []
# Packet 3 - Timestamp: 3.8310279846191406	Direction: -1	Data Size: 0	Flags: ['FIN']
# Packet 4 - Timestamp: 3.8676209449768066	Direction: 1	Data Size: 0	Flags: []
# ---


# In[1]:


import sys
import statistics
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
        print("Bucket\tFlow\tTimestamp\tDirection\tData Size\tFlags")

        flow_buckets = {}  # Dictionary to store flow buckets
        total_forward_packets = 0
        total_backward_packets = 0
        total_forward_bytes = 0
        total_backward_bytes = 0
        forward_interarrival_times = []
        backward_interarrival_times = []
        flow_interarrival_times = []
        active_interarrival_times = []
        idle_interarrival_times = []

        first_ts = None  # Variable to store the timestamp of the first packet

        for ts, buf in pcap:
            if first_ts is None:
                first_ts = ts  # Set the timestamp of the first captured packet

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

            bucket_index = int((ts - first_ts) // 2)  # Calculate the bucket index

            if bucket_index in flow_buckets:
                if flow in flow_buckets[bucket_index]:
                    flow_buckets[bucket_index][flow].append((ts, buf, tcp.sport, tcp.dport, len(tcp.data), tcp.flags))
                elif reverse_flow in flow_buckets[bucket_index]:
                    flow_buckets[bucket_index][reverse_flow].append((ts, buf, tcp.sport, tcp.dport, len(tcp.data), tcp.flags))
                else:
                    flow_buckets[bucket_index][flow] = [(ts, buf, tcp.sport, tcp.dport, len(tcp.data), tcp.flags)]
            else:
                flow_buckets[bucket_index] = {flow: [(ts, buf, tcp.sport, tcp.dport, len(tcp.data), tcp.flags)]}

        # Process flow buckets
        for bucket_index, flows in flow_buckets.items():
            forward_packets = 0
            backward_packets = 0
            forward_bytes = 0
            backward_bytes = 0
            flow_interarrival_time = 0
            last_packet_ts = None

            for flow, packets in flows.items():
                if len(packets) < 20:
                    continue  # Discard the bucket if it has less than 20 packets

                for idx, (ts, buf, src_port, dst_port, data_size, flags) in enumerate(packets):
                    eth = dpkt.ethernet.Ethernet(buf)
                    ip = eth.data
                    tcp = ip.data
                    direction = 1 if connection_id_to_str((ip.src, tcp.sport, ip.dst, tcp.dport)) == flow else -1
                    if direction == 1:
                        forward_packets += 1
                        forward_bytes += data_size
                    else:
                        backward_packets += 1
                        backward_bytes += data_size

                    if last_packet_ts is not None:
                        interarrival_time = ts - last_packet_ts
                        if direction == 1:
                            forward_interarrival_times.append(interarrival_time)
                        else:
                            backward_interarrival_times.append(interarrival_time)
                        flow_interarrival_times.append(interarrival_time)

                        if interarrival_time > 2.0:  # Idle period threshold (example value: 2.0 seconds)
                            idle_interarrival_times.append(interarrival_time)
                        else:
                            active_interarrival_times.append(interarrival_time)

                    last_packet_ts = ts

                    flag_names = []
                    if flags & dpkt.tcp.TH_SYN:
                        flag_names.append("SYN")
                    if flags & dpkt.tcp.TH_FIN:
                        flag_names.append("FIN")

                    print(f"{bucket_index}\t{flow}\t{ts - first_ts}\t{direction}\t{data_size}\t{flag_names}")

            total_forward_packets += forward_packets
            total_backward_packets += backward_packets
            total_forward_bytes += forward_bytes
            total_backward_bytes += backward_bytes

            print(f"Bucket {bucket_index} Summary:")
            print(f"Forward Packets: {forward_packets}")
            print(f"Backward Packets: {backward_packets}")
            print(f"Total Bytes per Second: {total_forward_bytes + total_backward_bytes}")
            print(f"Total Forward Bytes: {total_forward_bytes}")
            print(f"Total Backward Bytes: {total_backward_bytes}")
            print(f"---")

        print("Total Summary:")
        print(f"Total Forward Packets: {total_forward_packets}")
        print(f"Total Backward Packets: {total_backward_packets}")
        print(f"Total Bytes per Second: {total_forward_bytes + total_backward_bytes}")
        print(f"Total Forward Bytes: {total_forward_bytes}")
        print(f"Total Backward Bytes: {total_backward_bytes}")

        print("---")
        print("Interarrival Time Statistics:")
        print(f"Forward Interarrival Time - Mean: {statistics.mean(forward_interarrival_times)}")
        print(f"Forward Interarrival Time - Minimum: {min(forward_interarrival_times)}")
        print(f"Forward Interarrival Time - Maximum: {max(forward_interarrival_times)}")
        print(f"Forward Interarrival Time - Standard Deviation: {statistics.stdev(forward_interarrival_times)}")

        print(f"Backward Interarrival Time - Mean: {statistics.mean(backward_interarrival_times)}")
        print(f"Backward Interarrival Time - Minimum: {min(backward_interarrival_times)}")
        print(f"Backward Interarrival Time - Maximum: {max(backward_interarrival_times)}")
        print(f"Backward Interarrival Time - Standard Deviation: {statistics.stdev(backward_interarrival_times)}")

        print(f"Flow Interarrival Time - Mean: {statistics.mean(flow_interarrival_times)}")
        print(f"Flow Interarrival Time - Minimum: {min(flow_interarrival_times)}")
        print(f"Flow Interarrival Time - Maximum: {max(flow_interarrival_times)}")
        print(f"Flow Interarrival Time - Standard Deviation: {statistics.stdev(flow_interarrival_times)}")

        print(f"Active Interarrival Time - Mean: {statistics.mean(active_interarrival_times)}")
        print(f"Active Interarrival Time - Minimum: {min(active_interarrival_times)}")
        print(f"Active Interarrival Time - Maximum: {max(active_interarrival_times)}")
        print(f"Active Interarrival Time - Standard Deviation: {statistics.stdev(active_interarrival_times)}")

        print(f"Idle Interarrival Time - Mean: {statistics.mean(idle_interarrival_times)}")
        print(f"Idle Interarrival Time - Minimum: {min(idle_interarrival_times)}")
        print(f"Idle Interarrival Time - Maximum: {max(idle_interarrival_times)}")
        print(f"Idle Interarrival Time - Standard Deviation: {statistics.stdev(idle_interarrival_times)}")

analyze_pcap_file('E:\PPT Reader\http_ipv4_complex.cap')

# Bucket	Flow	Timestamp	Direction	Data Size	Flags
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.0	1	0	['SYN']
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.052906036376953125	-1	0	['SYN']
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.05294084548950195	1	0	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.052983999252319336	1	394	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.11489295959472656	-1	0	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.11852192878723145	-1	1448	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.11853599548339844	1	0	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.11969304084777832	-1	1448	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.11970996856689453	1	0	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.12064886093139648	-1	1448	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.12066006660461426	1	0	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.15792107582092285	-1	1448	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.15794801712036133	1	0	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.16084790229797363	-1	1448	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.16086697578430176	1	0	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.16356396675109863	-1	1448	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.1635758876800537	1	0	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.16584992408752441	-1	1448	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.16586089134216309	1	0	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.16829490661621094	-1	1448	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.1683049201965332	1	0	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.17022991180419922	-1	1289	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.17024803161621094	1	0	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.20525884628295898	1	452	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.2444610595703125	-1	496	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.24945998191833496	1	421	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.28720784187316895	-1	495	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.2873108386993408	1	425	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.32711005210876465	-1	502	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.32723307609558105	1	423	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.3706519603729248	-1	498	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.37079286575317383	1	424	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.4094369411468506	-1	498	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.4096200466156006	1	419	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.4471158981323242	-1	495	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.48822689056396484	1	0	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.639970064163208	1	421	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.6809289455413818	-1	495	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.6809430122375488	1	0	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.6810150146484375	1	419	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.7179288864135742	-1	495	[]
# 0	192.168.1.104:41849<=>67.205.52.141:80	0.7597248554229736	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.20777392387390137	1	0	['SYN']
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.249237060546875	-1	0	['SYN']
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.24925684928894043	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.24938392639160156	1	426	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.28623104095458984	-1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3043830394744873	-1	1448	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.30440306663513184	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3060338497161865	-1	1448	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3060438632965088	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3069939613342285	-1	1448	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3070030212402344	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3428220748901367	-1	1448	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.34283900260925293	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.34386301040649414	-1	1448	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.34387993812561035	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.346904993057251	-1	1448	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.34691691398620605	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.34802889823913574	-1	1448	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3480379581451416	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3494069576263428	-1	1448	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.34941697120666504	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.35040783882141113	-1	1448	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3504209518432617	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.38700103759765625	-1	1448	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3870229721069336	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3917560577392578	-1	1448	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.39177894592285156	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3948628902435303	-1	1448	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.39487695693969727	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3967628479003906	-1	176	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.3967759609222412	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.396867036819458	1	415	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.4540748596191406	-1	1448	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.4545118808746338	-1	193	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.4545259475708008	1	0	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.6404750347137451	1	425	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.6802589893341064	-1	502	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.6804039478302002	1	424	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.717540979385376	-1	498	[]
# 0	192.168.1.104:41850<=>67.205.52.141:80	0.7557289600372314	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	0.28197383880615234	1	0	['SYN']
# 0	192.168.1.104:41852<=>67.205.52.141:80	0.321760892868042	-1	0	['SYN']
# 0	192.168.1.104:41852<=>67.205.52.141:80	0.32176995277404785	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	0.32178807258605957	1	421	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	0.36988401412963867	-1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.4836549758911133	-1	1448	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.4836678504943848	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.485219955444336	-1	1448	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.485231876373291	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.4869489669799805	-1	1448	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.4869599342346191	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5252759456634521	-1	1448	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.525291919708252	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5262038707733154	-1	1448	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5262150764465332	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5267419815063477	-1	1448	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.526749849319458	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.527271032333374	-1	1448	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5272810459136963	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5280609130859375	-1	1448	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5280709266662598	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.528756856918335	-1	1448	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5287668704986572	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5697190761566162	-1	1448	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5697429180145264	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.570530891418457	-1	1448	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5705430507659912	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5714778900146484	-1	1448	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5714879035949707	1	0	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.5721728801727295	-1	906	[]
# 0	192.168.1.104:41852<=>67.205.52.141:80	1.57218599319458	1	0	[]
# Bucket 0 Summary:
# Forward Packets: 60
# Backward Packets: 53
# Total Bytes per Second: 61231
# Total Forward Bytes: 5909
# Total Backward Bytes: 55322
# ---
# Bucket 1 Summary:
# Forward Packets: 0
# Backward Packets: 0
# Total Bytes per Second: 61231
# Total Forward Bytes: 5909
# Total Backward Bytes: 55322
# ---
# Total Summary:
# Total Forward Packets: 60
# Total Backward Packets: 53
# Total Bytes per Second: 61231
# Total Forward Bytes: 5909
# Total Backward Bytes: 55322
# ---
# Interarrival Time Statistics:
# Forward Interarrival Time - Mean: -0.00890309527768927
# Forward Interarrival Time - Minimum: -0.5519509315490723
# Forward Interarrival Time - Maximum: 0.18594908714294434
# Forward Interarrival Time - Standard Deviation: 0.10070153791438345
# Backward Interarrival Time - Mean: 0.03957487952034428
# Backward Interarrival Time - Minimum: 0.00043702125549316406
# Backward Interarrival Time - Maximum: 1.1137709617614746
# Backward Interarrival Time - Standard Deviation: 0.15173877204332195
# Flow Interarrival Time - Mean: 0.014037374939237322
# Flow Interarrival Time - Minimum: -0.5519509315490723
# Flow Interarrival Time - Maximum: 1.1137709617614746
# Flow Interarrival Time - Standard Deviation: 0.12913652201982118
# Active Interarrival Time - Mean: 0.014037374939237322
# Active Interarrival Time - Minimum: -0.5519509315490723
# Active Interarrival Time - Maximum: 1.1137709617614746
# Active Interarrival Time - Standard Deviation: 0.12913652201982118


# In[ ]:




