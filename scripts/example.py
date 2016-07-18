#!/usr/bin/env python
# -*- coding:utf-8 -*-

def scan(scanner, ip):
    port = 80
    # write your code here
    
    output = {ip:{}}
    output[ip][port] = {'status': 'open'}
    output[ip][port]['service'] = 'unknown'
    output[ip][port]['message'] = 'hello world'
    scanner.put(output)