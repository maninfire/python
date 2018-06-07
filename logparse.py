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
f=open("test.log","r")
stre="王浩看看我们的回忆影集王浩看看我们的回忆影集王浩看看我们的回忆影集"
arr={}  
lines = f.readlines()  
for line in lines: 
    type=chardet.detect(line)
    linex=line.decode(type["encoding"])
    print stre.decode('utf-8').encode('gbk')
    ipaddress=re.compile('(.*)Qihoo_Sandbox(.*)')#(r'^#(((2[0-4]\d|25[0-5]|[01]?\d\d?)\.){3}(2[0-4]\d|25[0-5]|[01]?\d\d?))')  
    match=ipaddress.match(line)
    if match:  
        #print match
        mylist=match.group(0)
        print match.group(0).encode('gbk')
        #print match.group(1)        
        #print match.group(2)
        #ip = match.group()  
        #if(arr.has_key(ip)):  
           # arr[ip]+=1  
        #else:  
            #arr.setdefault(ip,1)  
