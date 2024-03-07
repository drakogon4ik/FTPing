"""
Author: Oleg Shkolnik יא9.
Description: Client program that send request packet to the server and waits for the response packets.
             It checks that packets haven't been lost and have all data.
Date: 7/03/24
"""


from scapy.all import *


ser_ip = '172.16.9.215'


def checking_packets(echo_packet, ack_packet, data):
    """
    function checks if packets received from the server haven't been lost and have all data
    :param echo_packet: packet with echo response from the server
    :param ack_packet: packet with ACK in raw from the server
    :param data: request that client input
    :return: true if packets haven't been lost and have all data
    """
    if ack_packet and Raw in ack_packet and ack_packet.getlayer(Raw).load.decode()[:3] == 'ACK':

        if echo_packet.getlayer(Raw).load.decode() != data:
            return False

        return True


def send_recv(destination_ip, data, flag=False):
    """
    function sends SYN packet and gets 2 answers from the server (first with echo response, second with ack response)
    :param destination_ip: ip on which function sends syn packet
    :param data: data that user want to send
    :param flag: flag for the loop to exit from it when we receive ack
    :return: answers from the server
    """

    echo_packet = b''
    ack_packet = b''

    while not flag:

        request_packet = IP(dst=destination_ip) / ICMP(type="echo-request") / data
        echo_packet = sr1(request_packet, timeout=1)
        ack_packet = sr1(request_packet, timeout=1)

        flag = checking_packets(echo_packet, ack_packet, data)

    return echo_packet, ack_packet


def main():
    """
    makes the loop in which asks for the message from client, creates packet and sends it
    loop works until client won't send message 'exit'
    function prints data from two packets that it received from the server
    """
    request = ''
    try:
        while request != 'exit':

            request = input('input message you want to send: (if you want to exit send message "exit") ')

            if request == 'exit':
                break

            response_packet = send_recv(ser_ip, request)

            for under_packet in response_packet:
                if under_packet and Raw in under_packet:
                    print(under_packet.getlayer(Raw).load.decode())

    except socket.error as err:
        """
        Send the name of error in error situation
        """
        print('Received socket error ' + str(err))


if __name__ == "__main__":
    
    main()
