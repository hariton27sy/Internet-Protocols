import argparse
import sys

import portscan


def parse(args):
    parser = argparse.ArgumentParser(description="Script for checking ports on host. Allows TCP and UDP ports,"
                                                 "and define define protocol, using this port.")

    parser.add_argument('-t', dest='tcp', action='store_true', help='Scan tcp ports. '
                                                                    'If tcp and udp flags both are absent,'
                                                                    'scanner checks only tcp ports.')
    parser.add_argument('-u', dest='udp', action='store_true', help='Scan udp ports. Require root user.')
    parser.add_argument('-p', '--ports', action='store', nargs=2, type=int, default=[1, 65535], help='Ports range to '
                                                                                                     'scan. By default '
                                                                                                     'scan all ports.')
    parser.add_argument('host', action='store', help='Host for scanning')

    args = parser.parse_args(args)
    if not args.tcp and not args.udp:
        args.tcp = True

    return args


def main(args):
    args = parse(args[1:])

    scanner = portscan.Scanner(args.host, args.ports[0], args.ports[1], args.tcp, args.udp, workers=20)
    try:
        scanner.start()
    except KeyboardInterrupt:
        scanner.stop()


if __name__ == "__main__":
    main(sys.argv)
