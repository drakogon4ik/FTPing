"""
Author: Oleg Shkolnik יא9.
Description: Server program that receives packet from the client, create two response packets: first - echo packet;
                                                                                                       second - ack packet.
             Packets that server sends can be lost with chance 1 to 10.
Date: 7/03/24
"""


from scapy.all import *


client_ip = '172.16.17.227'


def send_packet(req_packet, data):
    """
    function sends echo packet and ack packet on the ip from what it received request packet.
    packets that function sends can be lost with chance 1 to 10
    :param req_packet: request packet it gets from the client
    :param data: data from the client's request packet
    """

    random_number = random.randint(1, 10)

    echo_packet = IP(dst=req_packet[IP].src)/ICMP(type="echo-reply")/data

    ack_packet = IP(dst=req_packet[IP].src)/ICMP(type="echo-reply")/"ACK"

    print(random_number)

    if random_number != 1:

        send([echo_packet, ack_packet])


def main(client_packet):
    """
    check that client_packet is FTPING and sends response packets
    :param client_packet: client's request packet
    """
    try:
        if ICMP in client_packet and Raw in client_packet:
            print("Received FTPING packet:")

            print(client_packet.summary())

            user_data = client_packet[Raw].load.decode()

            send_packet(client_packet, user_data)

            print("sending echo response :", user_data)
    except socket.error as err:
        print('Received socket error ' + str(err))


if __name__ == "__main__":
    """
    We launch the sniffer and transfer received payments for processing
    """
    sniff(filter=f'icmp and src host {client_ip}', prn=main)
