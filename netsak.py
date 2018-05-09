import argparse as ap
from scapy.all import *
import sys
import os
import time

def get_args():
    '''
        Generate arguments
    '''
    parser = ap.ArgumentParser(description='Network swiss army knife')
    parser.add_argument('-s', help='packet sniffing')
    parser.add_argument('-f', help='OS fingerprinting')
    return parser.parse_args()

def main():
    args = get_args()


if __name__ == '__main__':
    #main()
    load_module("nmap")
    conf.nmap_base = 'nmap-os-fingerprints'
    score, fprint = nmap_fp("www.secdev.org")
    print(score)
    print(fprint)
