import nmap

def gen_ports_string(ports):
    return ','.join(ports)

def scan(nm, dic, host, param):
    ports = gen_ports_string([str(k) for k, v in dic[host][param].items() if v])
    args = '--script vuln {}'.format('-sT' if param == 'tcp' else '-sU')
    nm.scan(hosts=host, ports=ports, arguments=args)
    print('command:', nm.command_line())
    return nm

def show(nm):
    for host in nm.all_hosts():
        print('----------------------------------------')
        print('Host: {} ({})'.format(host, nm[host].hostname()))
        print('State: {}'.format(nm[host].state()))
        for proto in nm[host].all_protocols():
            print('------------')
            print('Protocol: {}'.format(proto))
            ports = list(nm[host][proto].keys())
            ports.sort()
            for port in ports:
                if 'script' in nm[host][proto][port]:
                    print('Possible vunerability!')
                    print('Port: {}\tState: {}'.format(port, state))
                    print('Advanced info: {}'.format(nm[host][proto][port]['script']))



# https://xael.org/pages/python-nmap-en.html
nm = nmap.PortScanner()
nm.scan(hosts='scanme.nmap.org', ports='20-1000')
print('command: ', nm.command_line())

vuln = {}

for host in nm.all_hosts():
    print('----------------------------------------')
    print('Host: {} ({})'.format(host, nm[host].hostname()))
    print('State: {}'.format(nm[host].state()))
    vuln[host] = {}
    for proto in nm[host].all_protocols():
        print('------------')
        print('Protocol: {}'.format(proto))
        ports = list(nm[host][proto].keys())
        ports.sort()
        vuln[host][proto] = {}
        for port in ports:
            state = nm[host][proto][port]['state']
            print('Port: {}\tState: {}'.format(port, state))
            vuln[host][proto][port] = True if state == 'open' or state != 'filtered' \
                                      else False

print('\n\nVulnerability Scan:\n')

for host in vuln:
    if 'tcp' in vuln[host]:
        show(scan(nm, vuln, host, 'tcp'))
    elif 'udp' in vuln[host]:
        show(scan(nm, vuln, host, 'udp'))
    else:
        continue
