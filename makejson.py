#!/usr/bin/python
# -*- coding: utf-8 -*-
import re
import chardet
import os
import sys
import subprocess
import time
reload(sys) 
sys.setdefaultencoding("utf-8")
def appwork(error):
    os.system('adb push test.json /data/local/tmp/hooks.json')
    time.sleep(1)
    os.system('adb shell am start -n com.th.lier.test/.MainActivity')
    time.sleep(1)
    fto=open("notwork.txt",'a')
    process = subprocess.Popen('adb shell "ps|grep com.th.lier.test"', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    process.wait()
    command_output = process.stdout.read()#.decode('gbk')
    if command_output=='':
        fto.writelines(error+'\n')
    fto.close()
    os.system('adb shell am force-stop com.th.lier.test')
    time.sleep(1)

def makejson():
    f=open("yuan.txt","r")
    lines = f.readlines()
    for line in lines:
        if os.path.exists('test.json'):
            os.system("del test.json")
        fto=open("test.json",'a')
        fto.writelines('{\n')
        fto.writelines('    "hookConfigs": [\n')
        ipaddress=re.compile('(.*)->(.*)')
        match=ipaddress.match(line)
        if match:
            fto.writelines('        {\n')
            fto.writelines('            '+'\"class_name\": \"'+match.group(1)+'\",\n')
            fto.writelines('            '+'\"method\": \"'+match.group(2)+'\",\n')
            fto.writelines('            '+'\"thisObject\": \"'+'false'+'\",\n')
            fto.writelines('            '+'\"type\": \"'+'fingerprint'+'\"\n')
            fto.writelines('        }\n')
        fto.writelines('    ],\n    "trace": false\n}') 
        fto.close()
        appwork(match.group(0))

def matchmethod():

    f=open("hooksbak.json","r")
    lines = f.readlines()
    ff=open("yuan.txt","r")
    matchf=open("match2.txt",'a')
    hooksbaklines = ff.readlines()
    for line in lines:
        ipaddress=re.compile('(.*)\"class_name\":.\"(.*)\"')
        match=ipaddress.match(line) 
        if match:
            matchf.writelines('yuan:'+match.group(0)+'\n')
        ipaddress=re.compile('(.*)\"method\":.\"(.*)\"')
        match=ipaddress.match(line)
        if match:
            #print match.group(0)
            matchf.writelines('yuan:'+match.group(0)+'\n')
            for hooksbakline in hooksbaklines:
                hookstr=re.compile('(.*)'+match.group(2)+'(.*)')
                hookmatch=hookstr.match(hooksbakline)
                if hookmatch:
                    #print 'got : '+hookmatch.group(0)
                    matchf.writelines('hook:'+hookmatch.group(0)+'\n')
    f.close()
    ff.close()
    matchf.close()

makejson()
