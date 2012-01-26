import logging
import pcapy
import struct

interface = 'wlan0'
target = './dhcp-cap'
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler())

def hwaddr_ascii(packet):
    # picking up MAC directly from ethernet frame
    return ':'.join('%02x' % ord(c) for c in packet[6:12])

def capture_dhcp(itf):
    f = open(target, 'w')
    reader = pcapy.open_live(itf, 4096, False, 5000)
    reader.setfilter('udp dst port 67')
    def callback(header, packet):
        hwaddr = hwaddr_ascii(packet)
        logger.info('Captured dhcp request from %s', hwaddr)
        f.write(hwaddr + '\n')
        f.flush()
    try:
        while True:
            reader.dispatch(1, callback)
    except KeyboardInterrupt:
        pass

capture_dhcp('wlan0')
