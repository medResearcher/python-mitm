from socket import *
network = '192.168.11.1.'

def is_up(addr):
    s = socket(AF_INET, SOCK_STREAM)
    s.settimeout(0.01)
    if not s.connect_ex((addr, 135)):
        s.close()
        
