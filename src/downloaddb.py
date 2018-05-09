try:
    from urllib.request import urlopen
except ImportError:
    from urllib2 import urlopen
    
open('nmap-os-fingerprints', 'wb').write(urlopen('https://raw.githubusercontent.com/nmap/nmap/9efe1892/nmap-os-fingerprints').read())
