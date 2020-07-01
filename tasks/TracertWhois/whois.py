import socket
import re

LOCAL_IPS = [
    ((10, 0, 0, 0), (255, 0, 0, 0)),
    ((172, 16, 0, 0, 12), (255, 240, 0, 0)),
    ((192, 168, 0, 0), (255, 255, 0, 0))
]


def is_local(ip: str):
    ip = list(map(int, ip.split('.')))
    nets = list(filter(lambda x: ip[0] == x[0][0], LOCAL_IPS))
    if not nets:
        return False
    addr, mask = nets[0]
    for i in range(4):
        if (ip[i] & mask[i]) != addr[i]:
            return False
    return True


def _get_whois_info(whois_server: str, address: str,
                    parser=lambda x: x.decode('utf8'), formatter=lambda x: x + b'\r\n'):
    if isinstance(address, str):
        address = address.encode('utf8')
    with socket.socket() as s:
        s.settimeout(2)
        s.connect((whois_server, 43))
        s.send(formatter(address))
        data = []
        last = b'1'
        while last:
            try:
                last = s.recv(65535)
                data.append(last)
            except socket.error:
                break

        return parser(b''.join(data))


def _default_parser(data: bytes):
    data = data.decode('utf8', errors='ignore')
    netname = re.findall(r'netname:\s*(.*?)\n', data, re.I)
    netname = netname[0] if netname else None
    origin = re.findall(r'origin\s?A?S?:\s*AS(\d*)\n', data, re.I)
    origin = origin[0] if origin else None
    country = re.findall(r'country:\s*(.*?)\n', data, re.I)
    country = country[0] if country and country[0] != 'EU' else None
    return netname, origin, country


def _define_whois_server(ip: str):
    data = _get_whois_info('whois.iana.org', ip)
    whois = re.search(r'whois:\s*(.*)\n', data)
    if whois:
        whois = whois.group(1)
        return whois


def who_is(ip: str):
    """Returns netname, origin, country"""
    netname = None
    country = None
    origin = None

    server = _define_whois_server(ip)
    if server:
        return _get_whois_info(server, ip, parser=_default_parser)

    return netname, origin, country

