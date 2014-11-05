#!/usr/bin/env python2.7
#-*- coding:utf-8 -*-

import httplib, urllib
import socket
import time
import os, sys
import fcntl
import struct
import json
import netifaces 

#settings:
EMAIL = "xxx@gmail.com" # replace with your email
PASSWORD = "ppp" # replace with your password
DOMAIN = "yeshiwei.cn" # replace with your domain
SUB_DOMAIN = "air" # replace with your sub_domain

#the next two setting will be setted by calling domain_list() and record_list(), if setted as None and empty dict.
DOMAIN_ID = None
RECORD_ID = dict()

current_ip = None

def domain_list():
    """
    List all the domains and get the global variable DOMAIN_ID
    """
    global DOMAIN_ID
    params = dict(
        login_email = EMAIL, 
        login_password = PASSWORD, 
        format = "json",
        record_line = "默认",
        )
    headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/json"}
    conn = httplib.HTTPSConnection("dnsapi.cn")
    conn.request("POST", "/Domain.List", urllib.urlencode(params), headers)
    response = conn.getresponse()
    print response.status, response.reason
    data = json.loads(response.read(), 'utf-8')
    for domain in data['domains']:
        print domain['name'], domain['id']
        if domain['name'] == DOMAIN:
            DOMAIN_ID = domain['id']
    print ''
    conn.close()
    return data

def record_list():
    """
    request and print the record list of the default domain
    """
    global RECORD_ID
    params = dict(
        login_email = EMAIL, # replace with your email
        login_password = PASSWORD, # replace with your password
        format="json",
        domain_id = DOMAIN_ID,
        record_line="默认",
        )
    headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/json"}
    conn = httplib.HTTPSConnection("dnsapi.cn")
    conn.request("POST", "/Record.List", urllib.urlencode(params), headers)
    response = conn.getresponse()
    print response.status, response.reason
    data = json.loads(response.read(), 'utf-8')
    for record in data['records']:
        print record['name'], record['id']
        RECORD_ID.update({record['name']:record['id']})
    print ''
    conn.close()
    return data

if DOMAIN_ID == None:
    domain_list()
if RECORD_ID == dict():
    record_list()

params  = dict(
    login_email = EMAIL, # replace with your email
    login_password = PASSWORD, # replace with your password
    format = "json",
    domain_id = DOMAIN_ID, # replace with your domain_id, can get it by API Domain.List
    sub_domain = SUB_DOMAIN, # replace with your sub_domain
    record_id = RECORD_ID[SUB_DOMAIN], # replace with your record_id, can get it by API Record.List
    record_line = "默认",
)

def ddns(ip, sub_domain=SUB_DOMAIN):
    """
    setting the dns record.
    """
    print "try setting %s.%s to %s" % (SUB_DOMAIN, DOMAIN, ip)
    params.update(dict(value=ip, sub_domain=sub_domain, record_id=RECORD_ID[sub_domain]))
    headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/json"}
    conn = httplib.HTTPSConnection("dnsapi.cn")
    conn.request("POST", "/Record.Ddns", urllib.urlencode(params), headers)
    
    response = conn.getresponse()
    print response.status, response.reason
    data = response.read()
    print data
    conn.close()
    return response.status == 200

def get_interface_ip(ifname):
    ip = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ip = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s',
                                                                          ifname[:15]))[20:24])
    except:
        pass
    if not ip:
        ip = netifaces.ifaddresses(ifname)[2][0]['addr']
    return ip

def get_lan_ip():
    ip = '127.0.0.1'
    if ip.startswith("127.") and os.name != "nt":
        candidate_interfaces = [
            "eth0",
            "eth1",
            "eth2",
            "en0",
            "wlan0",
            "wlan1",
            "wifi0",
            "ath0",
            "ath1",
            "ppp0",
            ]
        interfaces = netifaces.interfaces()
        for ifname in interfaces:
            if ifname not in candidate_interfaces:
                continue
            try:
                print ifname
                ip = get_interface_ip(ifname)
                break
            except IOError:
                pass
    return ip

def getip():
    """
    get ip by socket connecting. Sometimes, it can't get your local IP, but the IP of the net gateway.
    """
    sock = socket.create_connection(('ns1.dnspod.net', 6666))
    ip = sock.recv(16)
    sock.close()
    return ip

if __name__ == '__main__':
    if len(sys.argv) == 1:
        try:
            ip = get_lan_ip()
            print ip
            if current_ip != ip:
                if ddns(ip):
                    current_ip = ip
                    print "Succeeded"
        except Exception:
            pass
    if len(sys.argv) == 3:
        sub_domain=sys.argv[1]
        ip = "222.29.86."+sys.argv[2]
        print 'try to setting %s.%s to %s' %(sub_domain, DOMAIN, ip)
        if ddns(ip, sub_domain):
            print "Succeeded"
