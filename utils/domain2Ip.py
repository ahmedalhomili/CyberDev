import socket

def domain2ip(url):
    try:
        ip = socket.gethostbyname(url)
        return ip
    except socket.gaierror:
        return None