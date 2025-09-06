from scapy.all import IP, TCP, send

TARGET = '127.0.0.1'

for port in range(20, 102):
    p = IP(dst=TARGET)/TCP(dport=port, flags='S')
    send(p, verbose=False)
print('scan enviado')
