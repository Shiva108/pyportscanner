# Python Project for IT tech exam
try:
    import argparse
    import socket
    import threading
    import nmap
    import sys  # for exceptions
    import os  # for os exceptions
except ImportError.name:  # py 3.5 if 3.6 could have use ModuleNotFound
    print('Make sure modules are installed correctly! ')
except RuntimeError:
    print('Something went wrong! Module Import Runtime Error')


def udpscan(tgthost, tgtport):  # scans if udpport is up
    try:
        udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udps.settimeout(0.1)
        testmsg = '--- TEST LINE ---'
        udps.sendto(testmsg.encode(), (str(tgthost), int(tgtport)))
        udps.recvfrom(255)
        print('[+] udp ' + tgtport + ' is open ')
        udps.close()
    except socket.timeout or ConnectionError:
        print('[-] udp ' + tgtport + ' is closed')


def nmappingscan(tgthost):  # tests if host is up with the nmap -sn  -Pn host
    nmscan = nmap.PortScanner()
    nmscan.scan(hosts=tgthost, arguments='-sn -Pn')
    status = nmscan.scanstats()
    state = 'down'
    # print(str(state) + " " + status['uphosts'])
    if status['uphosts'] == "1":
        state = 'up'
    print('Host: ' + str(tgthost) + " is " + str(state))


def connscan(tgthost, tgtport):  # TCP connection attempt + banner grab
    try:
        conn_skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn_skt.settimeout(1)
        conn_skt.connect((tgthost, int(tgtport)))
        conn_skt.send(b'Information\r\n')
        results = str(conn_skt.recv(100))
        results = results[1:99]
        print('[+] tcp ' + str(tgtport) + " open " + '\nBanner: ' + results + '\n')
        conn_skt.close()
    except socket.timeout or ConnectionRefusedError or ConnectionError:
        print('[-] tcp ' + str(tgtport) + ' closed')
        return


def portscan(tgthost, tgtports):
    try:
        tgtip = socket.gethostbyname(tgthost)
    except socket.timeout:
        print("[-] Cannot resolve '%s': Unknown host" % tgthost)
        return
    try:
        tgtname = socket.gethostbyaddr(tgtip)
        print('\n[+] Scan Results for: ' + tgtname[0])
    except socket.timeout:
        print('\n[+] Scan Results for: ' + tgtip)
    # Threading
    for port in tgtports:  # Starts thread for each port
        t = threading.Thread(target=connscan, args=(tgthost, port))
        t.start()


def main():
    # Arguments
    parser = argparse.ArgumentParser(description='Port Scanner')
    parser.add_argument("tgthost", help='Target host that should be scanned')
    parser.add_argument("tgtport", help='Start scanning from this port')
    parser.add_argument("endport", help='Scan until this port')
    parser.add_argument('udpscan', help='Enable this for UDP scans')
    args = parser.parse_args()
    # Variables
    tgthost = args.tgthost
    tgtport = args.tgtport
    endport = args.endport
    udpflag = args.udpscan
    if tgtport.isnumeric() & endport.isnumeric():
        nextport = int(tgtport)
        tgtports = [tgtport]
        while nextport < int(endport):  # Fills up list of ports
            # print(nextport)
            nextport += 1
            tgtports.append(nextport)
        try:
            print(" ")
            nmappingscan(tgthost)
        except ConnectionError:
                print('NMAP ping scan failed (-sn), host is down?')
        except RuntimeError or WindowsError:
                print('Something went really wrong with NMAP ping')
        try:
            if udpflag == "u":
                try:
                    print(" ")
                    for port in tgtports:  # Starts thread for each port
                        t = threading.Thread(target=udpscan, args=(tgthost, str(port)))
                        t.start()
                except WindowsError or RuntimeError:
                    print('Function udpscan failed')
            else:
                try:
                    portscan(tgthost, tgtports)
                except WindowsError or RuntimeError:
                    print("Someting went wrong when calling portscan")
        except RuntimeError:
            print('This should happen: ', RuntimeError)
    else:
            print('Port numbers must be of format ii eg. 80')
            print('Hostname must be of format google.com or 127.0.0.1')
            print('-h for help.')


if __name__ == "__main__":
    main()
