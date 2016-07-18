This is a port scan tool.

    Usage: s0m3scan.py [options]

    Options:
      -h, --help  show this help message and exit
      -p PORT     the port to scan
      -s SCRIPT   the script to run
      -t IP       ip or ip file

Using `-p` option to config ports to scan. It can be used like this: `-p 80`, `-p 20-80`, `-p 21,22,23` or `-p 21,22,80-100`.

Using `-s` option to scan hosts with your own python script, the script should be like this.

    #!/usr/bin/env python
    # -*- coding:utf-8 -*-

    def scan(scanner, ip):
        port = 80

        # write your code here
    
        output = {ip:{}}
        output[ip][port] = {'status': 'open'}
        output[ip][port]['service'] = 'HTTP'
        output[ip][port]['message'] = 'hello world'
        scanner.put(output)

You can put your script file in the scripts folder and use it with it's name like this: `-s example`

Using `-t` option to config the target to scan, the target can be an ip string, or the path of an ip file, for example: `-t 127.0.0.1` or `-t ./ip.txt`.