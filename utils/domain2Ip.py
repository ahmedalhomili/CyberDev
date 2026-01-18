import socket

def domain2ip(url):
    try:
        # Remove protocol if exists
        url = url.replace("http://", "").replace("https://", "").split("/")[0]
        ip = socket.gethostbyname(url)
        return ip
    except socket.gaierror:
        return None