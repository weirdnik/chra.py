#! /usr/bin/env python -O
# -*- coding: utf-8 -*-

'''This is a tool for turnkey deployment of VPN server configuration
compatible with Android and iOS builtin VPN clients.

Usage:
%s <magic network number> <username_1> [<username_2> [... <username_n>]]

This script is based word-for-word on the Debian Wiki
Android VPN Server HOWTO: https://wiki.debian.org/HowTo/AndroidVPNServer

Copyright (C) 2018 Alexander Gütsche

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see http://www.gnu.org/licenses/.
'''

from __future__ import print_function

import os
import re
import sys
import subprocess
import fileinput
import string
import random

###

__version__ = '0.1'

###

FNAME = '99-ipsec-l2tp-vpn'
IFFNAME = os.path.join('/etc','network', 'interfaces.d', '.'.join((FNAME, 'cfg')))
FWNAME = os.path.join('/etc','sysctl.d', '.'.join((FNAME, 'conf')))

###

RE = re.compile('^([:\w]+): .*')
PACKAGES = ('racoon', 'xl2tpd', 'iptables', 'dnsmasq', 'iptables-persistent')
VPN = ('192','168')

###

L2TP = '''[global]
auth file = /etc/l2tpd/l2tp-secrets
rand source = dev
access control = no
ipsec saref = yes

[lns default]
local ip range = 192.168.%(magic)d.17-192.168.%(magic)d.31
ip range = 192.168.%(magic)d.65-192.168.%(magic)d.79
require authentication = yes
require chap = yes
refuse pap = yes
length bit = yes
name = xl2tpd
ppp debug = no
pppoptfile = /etc/ppp/peers/xl2tpd
length bit = yes
'''

RACOON = '''
log info;
path pre_shared_key "/etc/racoon/psk.txt";
path certificate "/etc/racoon/certs";

remote anonymous {
        exchange_mode main,aggressive;
        generate_policy on;
        nat_traversal on;
        dpd_delay 20;

        proposal {
                encryption_algorithm aes;
                hash_algorithm sha1;
                authentication_method pre_shared_key;
                dh_group modp1024;
        }
}

sainfo anonymous {
        encryption_algorithm aes, rijndael, 3des;
        authentication_algorithm hmac_sha1, hmac_md5;
        compression_algorithm deflate;
}

'''

POLICY = '''spdadd %(ip)s[l2tp] 0.0.0.0/0 udp -P out ipsec
        esp/transport//require;
spdadd 0.0.0.0/0 %(ip)s[l2tp] udp -P in ipsec
        esp/transport//require;
'''

PEER = '''auth
nodefaultroute
proxyarp
require-chap
ms-dns %s
'''

IPTABLES ='''iptables -t nat -A POSTROUTING -o %(ifname)s -s 192.168.%(magic)d.64/26 -j MASQUERADE
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -p udp --dport 500 -j ACCEPT
iptables -A INPUT -p udp --dport 4500 -j ACCEPT
iptables -A INPUT -p esp -j ACCEPT
iptables -A INPUT -p udp -m policy --dir in --pol ipsec -m udp --dport 1701 -j ACCEPT
'''

###

def gateway():

    '''Return the interface that default gateway traffic is routed thru.'''

    for line in fileinput.input('/proc/net/route'):
        if (not fileinput.isfirstline()) and (not int(line.split()[1], 16)):
            fileinput.close()
            return line.split()[0]


def interfaces():

    '''Returns list of defined network interfaces.'''

    return (RE.match(line).groups()[0]
            for line in subprocess.check_output('/sbin/ifconfig').split('\n')
            if RE.match(line))

def check_interfaces(magic, quiet=False):

    '''Check if <default gateway interface>:<magic number> interface alias exists.'''

    new = '%s:%d' % (gateway(), int(magic))
    for iface in interfaces():
        if iface == new:
            if not quiet or __debug__:
                print ('Interface %s already defined!' % new)
            return iface

def replace_config(filepath, body):

    '''Write a config file. If there's no previous backups, save old file as a backup.'''

    if os.path.exists(filepath):
        backup = '.'.join((filepath,'orig'))
        if not os.path.exists(backup) or __debug__:
            os.rename(filepath, backup)
        else:
            print('File %s already has a backup, skipping...')
        if not __debug__:
            with file(filepath, 'w') as handle:
                handle.write(body)

def passgen():

    '''Simple random password generator.'''

    vowels = 'aeiou'
    letters = string.ascii_letters
    numbers = string.digits
    separators = '_:-;~'

    result = ''
    for i in xrange(2):
        while random.randint(1,10) < 8 or len(result) < 10:
            result = result + ''.join(random.sample(set(letters), random.randint(1,3)))
            result = result + random.choice(vowels + numbers + vowels)
        result = result + str(random.choice(separators))
    return result[:16]
        
###
        
if __name__ == '__main__':

    if subprocess.check_output(('uname')).strip() != 'Linux' or not os.path.exists('/etc/debian_version'):
        print('Debian Linux and derivatives only, sorry!')
        sys.exit(1)

    try:
        number = sys.argv[1]
    except IndexError as error:
        number = 137
    finally:
        if check_interfaces(number) or number < 16: sys.exit(1)

    if len(sys.argv) < 3:
        print (__doc__ % sys.argv[0])
        sys.exit(1)
        
    ifname = ':'.join((gateway(), number))

    print('!\n! THIS SCRIPT WILL OVERWRITE YOUR NETWORKING AND IPSEC CONFIGURATIONS WITH NO REMORSE!\n!\n')
    response = raw_input('Enter "consent" without the quotes to confirm you that want that: ')
    if not response == 'consent': sys.exit(0)

    # Package install

    print('Installing required packages: %s' % ', '.join(PACKAGES) + '...')

    subprocess.call(('apt', '--assume-yes',
                     '--simulate' if __debug__ else '--quiet',
                     'install') + PACKAGES) 
    
    network = '.'.join(VPN + (str(number), '0'))
    interface = '.'.join(VPN + (str(number), '1'))

    # VPN Services interface definition

    if not __debug__:

        with file(IFFNAME, 'w') as handle:
            handle.write('# Android/iPhone internal VPN interface\n\n')
            handle.write('auto %s\n' % ifname)
            handle.write('interface %s inet static\n' % ifname)
            handle.write('\taddress %s\n' % interface)
            handle.write('\tnetmask 255.255.255.0\n')
            handle.close()
            #subprocess.call(('service', 'networking', 'restart'))
            subprocess.call (('ifup', '-i', IFFNAME, iface))
            if not check_interfaces(number, True):
                print('** Interface %s not up. Please ask a grownup for help.')

    # PPPd

    print('Configuring pppd... ',)
    if not __debug__: replace_config('/etc/ppp/peers/xl2tpd', PEER % interface)
    print ('done.')
    
    # DNSMasq
            
    print('Configuring DNSMasq... ', )
    if not __debug__:
        with file('/etc/dnsmasq.d/interfaces.conf', 'w') as handle:
            handle.write('listen-address=127.0.0.1\nlisten-address=%s\n' % interface)
            subprocess.call(('service', 'dnsmasq', 'force-reload'))
    print ('done.')

    # IP Forwarding
    
    print('Configuing IP forwarding (IPv4):')
    sysctl = ('net.ipv4.tcp_syncookies=1','net.ipv4.ip_forward=1')

    if not __debug__:
        with file(FWNAME) as handle:
            handle.write('# Android/iPhone VPN forwarding\n\n')
            handle.write('%s\n' % '\n'.join(sysctl))
            for item in sysctl:
                subprocess.call(('sysctl', item))

        replace_config('/etc/xl2tpd/xl2tpd.conf', L2TP % dict(magic=number))

        with file(' /etc/ppp/chap-secrets', 'a') as handle:
            handle.write('\n#xl2tp accounts automatically added\n')
            for user in sys.argv[2:]:
                passwd = passgen()
                handle.write('%s xl2tpd %s *' % (user, passwd))
                print('VPN user: %s\tVPN password: %s\n' % (user, passwd))

    ### IPSec configuration

    shs = passgen()
    
    replace_config('/etc/racoon/psk.txt', '# shared secret\n\n*\t%s\n' % shs)
    replace_config('/etc/racoon/racoon.conf', RACOON)

    print('!!! Your shared secret is: %s' % shs)

    # IPSec NAT Policy

    ## Finding outbound interface IP address
    
    ifip_re = re.compile('inet (\d+\.\d+\.\d+\.\d+)\/')
    ifconfig = subprocess.check_output(['ip','addr', 'show'])
    
    addrs = [ match.groups()[0] for match in ifip_re.finditer(ifconfig)
              if not (match.groups()[0].startswith('127.0.0')
                      or match.groups()[0].startswith('192.168'))]
    
    local_ip = addrs[0]
    
    print('Creating IPSec NAT policy for %s... ' % local_ip,)
    if not __debug__: replace_config('/etc/ipsec-tools.d/xl2tp.conf', POLICY % dict(ip=local_ip))
    print('done!')
    
    ### NAT Firewall

    print ('Flushing NAT and configuring IP masquerading...',)

    if not __debug__:
        subprocess.call(('iptables', '-t', 'nat', '--flush'))

        for line in IPTABLES.split('\n'):
            subprocess.call([item % dict(ifname=ifname, magic=number)
                             for item in line.split()])

        subprocess.call(['service', 'netfilter-persistent', 'save'])
    
    print('done.')

    if not __debug__:
        for service in ('xl2tpd', 'setkey', 'racoon', 'dnsmasq'):
            subprocess.call(('service', service, 'restart'))

    print('\nDone!\n\nYou can now try to connect to your new VPN server at %s!\n' % local_ip)
