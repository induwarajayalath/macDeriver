#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import fcntl
import socket
import struct
import hashlib 
import base64
import netifaces


inputInterfaceName = netifaces.interfaces()

def getHwAddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', bytes(ifname, 'utf-8')[:15]))
    return ':'.join('%02x' % b for b in info[18:24])


def main():
	f = open("upload_this_file.txt", "w")
	f.write('linux\n')
	toHash = ''
	for x in inputInterfaceName:
		n = 'hardware : '+x+'\nmac : '+getHwAddr(x)+'\n'
		toHash += n+'-newLinetoHash-'
		message_bytes = n.encode('ascii')
		base64_bytes = base64.b64encode(message_bytes)
		base64_message = base64_bytes.decode('ascii')
		f.write('%s\n'%(n))
	hash =  hashlib.sha512(toHash.encode()) 
	f.write('eof-')
	f.write('%s\n'%(hash.hexdigest()))
	f.close()
	# print (toHash)


if __name__ == "__main__":
    main()