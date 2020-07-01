import sys
import os
import socket
import argparse
import traceroute
import whois


def is_root_user():
    if os.name == 'nt':
        try:
            with open("C:\\Windows\\system.ini", 'r+'):
                pass
        except OSError:
            return False
        return True

    return 'SUDO_USER' in os.environ and os.geteuid() == 0


def check_correct_ip(ip: str):
    splitted = ip.split('.')
    if len(splitted) != 4:
        return False
    for a in splitted:
        try:
            if int(a) > 255 or int(a) < 0:
                return False
        except Exception:
            return False

    return True


def parse_args(args, host_ips):
    available_hosts = 'Available interface ips:\r\n' + "\r\n".join(map(lambda x: " - " + x, host_ips))
    parser = argparse.ArgumentParser(description="Simple TraceRoute with additional information from WhoIs service.\n"
                                                 f"It works only from root user.")

    parser.add_argument('interface_ip', action='store', help='ip address of network interface, that will '
                                                             'be listened. Format - xxx.xxx.xxx.xxx')
    parser.add_argument('dest_ip', action='store', help='Destination ip. Format - xxx.xxx.xxx.xxx\nIt also '
                                                        'can be dns address')
    parser.add_argument('depth', action='store', type=int, nargs='?', default=15, help='Max TTL')

    parsed = parser.parse_args(args)

    if not check_correct_ip(parsed.interface_ip) or parsed.interface_ip not in host_ips:
        sys.stderr.write("Enter correct interface ip. Available Host IPs:\n" + available_hosts)
        exit(2)

    if parsed.depth < 1:
        sys.stderr.write("Enter correct depth")
        exit(2)

    return parser.parse_args(args)


def main(args):
    host_ips = socket.gethostbyname_ex(socket.gethostname())[2]
    args = parse_args(args[1:], host_ips)
    if not is_root_user():
        print("You should run this script under root user")
        return

    try:
        args.dest_ip = socket.gethostbyname(args.dest_ip)
    except socket.error:
        print(f"Address {args.dest_ip} is not correct. Please enter the correct address")
        exit(2)

    counter = 1
    for i in traceroute.get_trace(args.interface_ip, args.dest_ip, args.depth):
        to_print = [str(counter), '. ', i, '\r\n']
        if i != '*':
            if whois.is_local(i):
                to_print.append('local')
            else:
                data = whois.who_is(i)
                data = filter(lambda x: x, data)
                to_print.append(', '.join(data))
            to_print.append('\r\n')
        to_print.append('\r\n')
        print(''.join(to_print), end='')

        counter += 1


if __name__ == "__main__":
    main(sys.argv)
