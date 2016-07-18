#!/usr/bin/env python
# -*- coding:utf-8 -*-

import socket
import sys
import threading
import time
from Queue import Queue
import os
import re
import optparse

NORMAL = 0
ERROR = 1

class Scan(object):
    def __init__(self, target, port, script):
        self.portList = []
        self.ipList = []
        self.script = script
        self.queue = Queue()
        self.Done = False
        self.lock = threading.Lock()
        if os.path.isfile(target):
            self.manageIP(target)
        else:
            self.ipList.append(target)

        if self.script:
            script_path = "%s/scripts/" % os.getcwd()
            if not script_path in sys.path:
                sys.path.append(script_path)
            self.script_ = __import__(self.script)

        if port:
            self.managePort(port)

    def start(self):
        length = len(self.ipList)
        for pos in xrange(0, length, 20):
            threads = []
            for num in range(pos, pos + 20):
                if num < length and not self.Done:
                    if self.script:
                        t = threading.Thread(target = self.script_.scan, args = (self.queue, self.ipList[num]))
                    else:
                        t = threading.Thread(target = self.scan, args = (self.ipList[num],))
                    threads.append(t)

            for t in threads:
                t.start()

            for t in threads:
                t.join()

        self.Done = True

    def manageIP(self, ipFile):
        fp = open(ipFile)
        for line in fp:
            if re.search(r'(?:\d{1,3}\.){3}\d{1,3} +(?:\d{1,3}\.){3}\d{1,3}', line):
                ipSegment = re.findall(r'((?:\d{1,3}\.){3}\d{1,3}) +((?:\d{1,3}\.){3}\d{1,3})', line)
                for ip in ipSegment:
                    startip = self.ip2num(ip[0])
                    endip = self.ip2num(ip[1])

                    while startip <= endip:
                        self.ipList.append(self.num2ip(startip))
                        startip = startip + 1

            elif re.search(r'(?:\d{1,3}\.){3}\d{1,3}', line):
                ip = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', line)
                self.ipList.append(ip[0])

    def ip2num(self, ip):
        ip = [int(x) for x in ip.split('.')]
        return ip[0]<<24 | ip[1]<<16 | ip[2]<<8 | ip[3]

    def num2ip(self, num):
        return '%s.%s.%s.%s' % ((num & 0xff000000) >> 24, (num & 0x00ff0000) >> 16, (num & 0x0000ff00) >> 8, num & 0x000000ff)

    def managePort(self, port):
        if isinstance(port, str):
            if ',' in port:
                tmpList = port.split(',')
                for port_ in tmpList:
                    if '-' in port_:
                        portRange = port_.split('-')
                        if len(portRange) != 2:
                            print "input port error!"
                            sys.exit()
                        else:
                            startPort = int(portRange[0])
                            endPort = int(portRange[1])
                            self.portList = self.portList + range(startPort, endPort + 1)
                    else:
                        self.portList.append(int(port_))

            elif '-' in port:
                portRange = port.split('-')
                if len(portRange) != 2:
                    print "port input error!"
                    sys.exit()
                else:
                    startPort = int(portRange[0])
                    endPort = int(portRange[1])
                    self.portList = range(startPort, endPort + 1)

            else:
                self.portList.append(port)

        else:
            print "port input error!"
            sys.exit()

    def scan(self, ip):
        output = {ip:{}}
        for port in self.portList:
            try:
                cs=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                cs.settimeout(10)
                address=(str(ip),int(port))
                status = cs.connect_ex((address))
                if status == NORMAL:
                    self.lock.acquire()
                    output[ip][port] = {'status': 'open'}
                    output[ip][port]['service'] = 'unknown'
                    self.queue.put(output)
                    self.lock.release()
            except Exception ,e:
                print ERROR
                print "error:%s" % e
                return ERROR
            cs.close()

        return NORMAL

    def output(self):
        while not self.queue.empty() or not self.Done:
            if not self.queue.empty():
                info = self.queue.get()
                ip = info.keys()[0]
                print "\n%s is open" % ip
                for port in info[ip]:
                    print "%s %s" % (port, info[ip][port]['status'])
                    for key in info[ip][port]:
                        if key != 'status':
                            print "%s: %s" % (key, info[ip][port][key])

    def run(self):
        threads = []
        t1 = threading.Thread(target = self.start)
        threads.append(t1)
        t2 = threading.Thread(target = self.output)
        threads.append(t2)

        for t in threads:
            t.setDaemon(True)
            t.start()

        while not self.Done:
            try:
                time.sleep(0.1)
            except KeyboardInterrupt,e:
                print '[!]User aborted, wait all slave threads to exit...'
                self.Done = True

if __name__ == '__main__':
    usage = "usage: %prog [options] "
    parse = optparse.OptionParser(usage = usage)
    parse.add_option("-p", dest = "port", action = "store", help = "the port to scan")
    parse.add_option("-s", dest = "script", action = "store", help = "the script to run")
    parse.add_option("-t", dest = "ip", action = "store", help = "ip or ip file")
    (options, args) = parse.parse_args()
    if not options.port:
        options.port = None
    if not options.script:
        options.script = None
    if not options.ip:
        print "please config the ip or ip file!"
        sys.exit()

    if not options.port and not options.script:
        print "please config the port or script!"
        sys.exit()

    t_scan = Scan(options.ip, options.port, options.script)
    t_scan.run()