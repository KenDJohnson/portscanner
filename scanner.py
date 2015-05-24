#!/usr/bin/python
import socket
import argparse
__author__ = 'ken'



def tcp_scan(ip, timeo, verbose, start, end, specific):
    open_ports = []
    timedout = []
    if not start:
        start = 1
    if not end:
        end = 65535
    if specific:
        start = specific
        end = specific + 1
    for port in range(start, end):
        if verbose:
            print("[+] Trying port %d..." % port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeo)
        result = sock.connect_ex((ip, port))
        if result == 0:
            print("[*] Port %d is open" % port)
            open_ports.append(port)
            sock.shutdown(socket.SHUT_RD)
            sock.close()
        elif result == 11:
            if verbose:
                print("[-] Connection timed out")
            timedout.append(port)
    return (open_ports, timedout)

def get_header(ip, ports, verbose):
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        send = [1, 2, 3]
        if result == 0:
            print("[*] Connecting to port %d" % port)
            sock.send(bytearray(send))
            try:
                buf = sock.recv(4096)
                print("[*] Header: \n %s " % buf)
            except socket.timeout:
                if input("[-] Connection on port %d timed out; retry with longer timeout? (y/n) " % port).lower() == "y":
                    sock.settimeout(10)
                    sock.send(bytearray(send))
                    try:
                        buf = sock.recv(4096)
                        print("[*] Header:\n %s" % buf)
                    except socket.timeout:
                        print("[-] Socket still timed out. Probably no header. Sucks for you.")
                        pass
                pass
        elif result == 111:
            print("[-] Connection refused")
        else:
            print("[-] Could not connect to port %d; Error code %d" % (port, result))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", help="TCP scan", action="store_true")
    parser.add_argument("ip", type=str, help="ip address to scan")
    parser.add_argument("-v", help="verbose output", action="store_true")
    parser.add_argument("-g", help="get headers from open ports", action="store_true")
    parser.add_argument("-s", type=int, help="start scanning at port")
    parser.add_argument("-e", type=int, help="end scanning at port")
    parser.add_argument("-p", type=int, help="scan a specific port")
    args = parser.parse_args()

    if not args.ip:
        parser.print_usage()

    if args.t:
        (open_ports, timedout) = tcp_scan(args.ip, 0.01, args.v, args.s, args.e, args.p)

        if len(timedout) >= 1:
            if input("Some ported timed out, try them with longer timeout? (yes/no)").lower() == "yes":
                tcp_scan(args.ip, 5)

    if args.g:
        get_header(args.ip, open_ports, args.v)
    else:
        for p in open_ports:
	        print("[*] Port %d is open" % p)



if __name__ == '__main__':
    main()