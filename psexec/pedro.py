import os

domain = raw_input('Domain: ')
login = raw_input('Login: ')
pwd = raw_input('Password: ')
os.system('python2 ../impacket/examples/psexec.py {}:{}@{} cmd.exe -path \
           c:\\\\windows\\\\system32'.format(login, pwd, domain))
