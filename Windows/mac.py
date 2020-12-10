#python3
from subprocess import check_output
from xml.etree.ElementTree import fromstring
from ipaddress import IPv4Interface, IPv6Interface
import hashlib 
import base64

def getNics() :

    cmd = 'wmic.exe nicconfig get MACAddress,Caption /format:rawxml'
    xml_text = check_output(cmd, creationflags=8)
    xml_root = fromstring(xml_text)

    nics = []
    keyslookup = {
        # 'DNSHostName' : 'hostname',
        # 'IPAddress' : 'ip',
        # 'IPSubnet' : '_mask',
        'Caption' : 'hardware',
        'MACAddress' : 'mac',
        # 'DefaultIPGateway' : 'gateway',
    }

    for nic in xml_root.findall("./RESULTS/CIM/INSTANCE") :
        # parse and store nic info
        n = {
            # 'hostname':'',
            # 'ip':[],
            # '_mask':[],
            'hardware':'',
            'mac':'',
            # 'gateway':[],
        }
        for prop in nic :
            name = keyslookup[prop.attrib['NAME']]
            if prop.tag == 'PROPERTY':
                if len(prop):
                    for v in prop:
                        n[name] = v.text
            elif prop.tag == 'PROPERTY.ARRAY':
                for v in prop.findall("./VALUE.ARRAY/VALUE") :
                    n[name].append(v.text)

        # append only which has macs
        if n['mac']!='':
            nics.append(n)
    return nics

if __name__ == '__main__':
    f = open("upload_this_file.txt", "w")
    f.write('windows\n')
    toHash = ''
    nics = getNics()
    for nic in nics :
        for k,v in nic.items() :
            # print('%s : %s'%(k,v))
            n =('%s : %s'%(k,v))
            toHash += n+'-newLinetoHash-'
            message_bytes = n.encode('ascii')
            base64_bytes = base64.b64encode(message_bytes)
            base64_message = base64_bytes.decode('ascii')
            f.write('%s\n'%(base64_message))
        # print()
        f.write('\n')
    hash =  hashlib.sha512(toHash.encode()) 
    f.write('eof-')
    f.write('%s\n'%(hash.hexdigest()))
    # f.write(toHash)
    f.close()