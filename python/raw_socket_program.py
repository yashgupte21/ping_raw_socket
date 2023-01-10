import socket
import os
import struct
import time
import select

s = socket.socket(socket.AF_INET, socket.SOCK_RAW,socket.getprotobyname("icmp"))


def sending(icmpPacket, addr):
    s.sendto(icmpPacket, (addr, 1234))
    return s, addr


def message(seq):
    icmp_type = 8
    icmp_code = 0
    icmp_check_sum = 0
    icmpID = os.getpid() & 0xffff

    # data = bytes(data)
    data_part = b'a'

    f = open('request.txt', 'a+')
    f.write("The data part %s\r\n" % str(data_part))

    send_packet = struct.pack('>BBHHH248s', icmp_type, icmp_code,
                              icmp_check_sum, icmpID, seq, data_part)

    print("the icmp_type, icmp_code,icmp_check_sum, icmpID, seq, data_part", icmp_type, icmp_code,icmp_check_sum, icmpID, seq, data_part)

    print("the length of the data_part",len(data_part))

    # checksums
    icmp_check_sum = check_sum(send_packet)

    send_packet = struct.pack('>BBHHH248s', icmp_type, icmp_code,
                              icmp_check_sum, icmpID, seq, data_part)

    f.write("The length of the sending packet %s\r\n" % str(len(send_packet)))

    f.write("The icmp packet requested %s\r\n" % str(send_packet))

    '''for i in range(2):
        i += 1
        pckt = sending(i)

    rawsocket, destAddr = connection(address, pckt)

    rcvd_packet, rcvdAddr = rawsocket.recvfrom(1024)

    icmp_type, icmp_code, checksum, packet_id, sequence = struct.unpack(">BBHHH", icmpHdr)

    if icmp_type == 0:

        f.write("The address of the received packet from the receive function %s\r\n" % str(rcvdAddr))

        f.write("The received packet from the receive function %s\r\n" % str(rcvd_packet))'''


    return send_packet


def check_sum(data_part):
    dlen = len(data_part)
    val = dlen % 2
    temp_sum = 0
    for i in range(0, dlen - val, 2):

        temp_sum += (data_part[i]) + ((data_part[i + 1]) << 8)
        if val:
            temp_sum += (data_part[-1])

        while temp_sum >> 16:
            temp_sum = (temp_sum >> 16) + (temp_sum & 0xffff)

    ans = ~temp_sum & 0xffff

    ans = ans >> 8 | (ans << 8 & 0xff00)
    return ans

def receive(rawsocket, pingTime, timeout=1):

    while True:
        # Start time
        started_time = time.time()

        recvr = select.select([rawsocket], [], [], timeout)
        # Wait time
        waitTime = (time.time() - started_time)
        # If it is timeout no content is returned
        if recvr[0] == []:
            return -1, -1
        # receiving time
        rcvd_time = time.time()
        # we are setting the bytes of the received packet to 1024 bytes
        rcvd_packet, rcvdAddr = rawsocket.recvfrom(1024)

        length = len(rcvd_packet) - 20

        f = open("reply.txt","a+")

        f.write("The length of the received packet %s\r\n" % str(length))

        f.write("The address of the received packet %s\r\n" % str(rcvdAddr))

        f.write("The received packet %s\r\n" % str(rcvd_packet))

        timeout = timeout - waitTime
        if timeout <= 0:
            return -1, -1, -1

        # TTL will be ip of message
        ttl = rcvd_packet[8]
        # we are taking the header part from the received packet
        icmpHdr = rcvd_packet[20:28]
        f.write("The icmp header of the received packet %s\r\n" % str(icmpHdr))

        #we have unpacked the packet into icmp_type, icmp_code, checksum
        icmp_type, icmp_code, checksum, packet_id, sequence = struct.unpack(">BBHHH", icmpHdr)

        if icmp_type == 0:
            f.write("The icmp packet type is  Echo Reply\r\n")
            return rcvd_time - pingTime, sequence, ttl


def ping_command(host, noMsgs=2, timeout=2):
    address = socket.gethostbyname(host)  # obtain ip Address
    print(" Ping {0} [{1}] have 256 Bytes of data :".format(host, address))
    timeLost = 0
    timeAccept = 0
    temptime = 0.0
    # Count the time of all packets send-receive
    count = []
    for i in range(noMsgs):
        i += 1
        icmp_pckt = message(i)

        rawsocket, destAddr = sending(icmp_pckt, address)

        replyTime, sequence, ttl = receive(rawsocket, time.time(), timeout)
        if replyTime >= 0:
            replyTime = replyTime * 1000
            print(" From {0} Reply to : byte =256 seq = {1} Time ={2:.2f}ms TTL={3}".format(destAddr, sequence, replyTime,ttl))
            timeAccept += 1
            temptime += replyTime
            count.append(replyTime)
        else:
            print(" timeout for request ")
            timeLost += 1
            count.append(timeout * 1000)


    # Statistics are not required for the project
    '''print('{0} Of Ping Statistics :'.format(address))
    print('\t Data packets : sent = {0}, received = {1},  loss  = {2} ({3}%  loss  ),'.format(noMsgs, timeAccept, timeLost, timeLost // (timeLost + timeAccept) * 100,))
    print(' time estimated of send receive ( In Milliseconds ):')
    print('\t  avg = {0:.2f}ms, short = {1:.2f}ms, long = {2:.2f}ms'.format(sum(count) // (timeLost + timeAccept),min(count), max(count)))'''


ping_command("127.0.0.1")
