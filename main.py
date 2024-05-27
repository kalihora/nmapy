import nmap

scanner = nmap.PortScanner()

target = "TARGET IP ADRESS HERE"

options = "DEFINE OPTIONS HERE LIKE -> -sS -sV -O -A -p"

scanner.scan(target, arguments=options)

for host in scanner.all_hosts():
    print("Host: ", host)
    print("State: ", scanner[host].state())
    for proto in scanner[host].all_protocols():
        print("Protocol: ", proto)
        ports = scanner[host][proto].keys()
        for port in ports:
            print("Port: ", port, "State: ", scanner[host][proto][port]['state'])
