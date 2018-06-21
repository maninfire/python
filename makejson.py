#!/usr/bin/python
# -*- coding: utf-8 -*-
import re
import chardet
import sys
reload(sys) 
sys.setdefaultencoding("utf-8")
'''python3
import importlib 
importlib.reload(sys
'''
f=open("yuan.txt","r")
fto=open("test.json",'a')
lines = f.readlines()  
for line in lines: 
    type=chardet.detect(line)
    linex=line.decode(type["encoding"])
    ipaddress=re.compile('(.*)->(.*)')#(r'^#(((2[0-4]\d|25[0-5]|[01]?\d\d?)\.){3}(2[0-4]\d|25[0-5]|[01]?\d\d?))')  
    match=ipaddress.match(line)
    if match:  
        fto.writelines('        {\n')
        fto.writelines('            '+'\"class_name\": \"'+match.group(1)+'\",\n')
        fto.writelines('            '+'\"method\": \"'+match.group(2)+'\",\n')
        fto.writelines('            '+'\"thisObject\": \"'+'false'+'\",\n')
        fto.writelines('            '+'\"type\": \"'+'fingerprint'+'\"\n')
        fto.writelines('        },\n')
