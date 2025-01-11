from scapy.all import sniff, TCP

def packet_process(packet): # packet processing
    if packet.haslayer(TCP): # we check the packet for a TCP packet phenomenon and whether the FIN PUSH URG flags are set there
        tcp_lay = packet.getlayer(TCP)
        if tcp_lay.flags == 0x29:
            print('Smas scanning was detected')
            print(f'[ INFO ] {packet.summary()}')

def main():
    print('\t\t---Xmas scan detector---\n\t\texit -> ctrl+C')
    sniff(filter='tcp', prn = packet_process, store = 0)


if __name__ == '__main__':
    main()
