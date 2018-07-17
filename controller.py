################################################################################
# (c) 2011, The Honeynet Project
# Author: Patrik Lantz patrik@pjlantz.com and Laurent Delosieres ldelosieres@hispasec.com
#
# This program is free software you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#
################################################################################

"""Analyze dynamically Android applications

This script allows you to analyze dynamically Android applications. It installs, runs, and analyzes Android applications.
At the end of each analysis, it outputs the Android application's characteristics in JSON.
Please keep in mind that all data received/sent, read/written are shown in hexadecimal since the handled data can contain binary data.
"""

import sys, json, time,   os, inspect#,curses,signal,
import zipfile, StringIO
import tempfile, shutil
import operator
import subprocess
import thread, threading
import re

from threading import Thread
from xml.dom import minidom
from subprocess import call, PIPE, Popen
from utils import AXMLPrinter
import hashlib
from pylab import *
import matplotlib
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle
from matplotlib.font_manager import FontProperties

from collections import OrderedDict

workavdip = []
freeavdip=[]

sendsms = {}
phonecalls = {}
cryptousage = {}
dexclass = {}
dataleaks = {}
opennet = {}
sendnet = {}
recvnet = {}
closenet = {}
fdaccess = {}
servicestart = {}
accessedfiles = {}

tags = { 0x1 :   "TAINT_LOCATION",      0x2: "TAINT_CONTACTS",        0x4: "TAINT_MIC",            0x8: "TAINT_PHONE_NUMBER",
         0x10:   "TAINT_LOCATION_GPS",  0x20: "TAINT_LOCATION_NET",   0x40: "TAINT_LOCATION_LAST", 0x80: "TAINT_CAMERA",
         0x100:  "TAINT_ACCELEROMETER", 0x200: "TAINT_SMS",           0x400: "TAINT_IMEI",         0x800: "TAINT_IMSI",
         0x1000: "TAINT_ICCID",         0x2000: "TAINT_DEVICE_SN",    0x4000: "TAINT_ACCOUNT",     0x8000: "TAINT_BROWSER",
         0x10000: "TAINT_OTHERDB",      0x20000: "TAINT_FILECONTENT", 0x40000: "TAINT_PACKAGE",    0x80000: "TAINT_CALL_LOG",
         0x100000: "TAINT_EMAIL",       0x200000: "TAINT_CALENDAR",   0x400000: "TAINT_SETTINGS" }


emulatorpath="D:\\Users\\andorid\\sdk\\tools\\"
monkeyrunnerpath="D:\\Users\\andorid\\sdk\\tools\\bin\\"
class CountingThread(Thread):
    """
    Used for user interface, showing in progress sign 
    and number of collected logs from the sandbox system
    """

    def __init__ (self):
        """
        Constructor
        """
        
        Thread.__init__(self)
        self.stop = False
        self.logs = 0
        
    def stopCounting(self):
        """
        Mark to stop this thread 
        """
        
        self.stop = True
        
    def increaseCount(self):
        
        self.logs = self.logs + 1

    def run(self):
        """
        Update the progress sign and 
        number of collected logs
        """
        
        signs = ['|', '/', '-', '\\']
        counter = 0
        while 1:
            sign = signs[counter % len(signs)]
            sys.stdout.write("     \033[132m[%s] Collected %s sandbox logs\033[1m   (Ctrl-C to view logs)\r" % (sign, str(self.logs)))
	    sys.stdout.flush()
            time.sleep(0.5)
            counter = counter + 1
            if self.stop:
                sys.stdout.write("   \033[132m[%s] Collected %s sandbox logs\033[1m%s\r" % ('*', str(self.logs), ' '*25))
		sys.stdout.flush()
                break
               
class Application:

    """
    Used for extracting information of an Android APK
    """
    def __init__(self, filename):
		self.filename = filename
		self.packageNames = []
		self.enfperm = []
		self.permissions = []
		self.recvs = []
		self.activities = {}
		self.recvsaction = {}

		self.mainActivity = None
    def processAPK(self):
		xml = {}
		error = True
		try:
			zip = zipfile.ZipFile(self.filename)

			for i in zip.namelist() :
				if i == "AndroidManifest.xml" :
					try :
						xml[i] = minidom.parseString( zip.read( i ) )
					except :
						xml[i] = minidom.parseString( AXMLPrinter( zip.read( i ) ).getBuff() )

					for item in xml[i].getElementsByTagName('manifest'):
						self.packageNames.append( str( item.getAttribute("package") ) )

					for item in xml[i].getElementsByTagName('permission'):
						self.enfperm.append( str( item.getAttribute("android:name") ) )

					for item in xml[i].getElementsByTagName('uses-permission'):
						self.permissions.append( str( item.getAttribute("android:name") ) )

					for item in xml[i].getElementsByTagName('receiver'):
						self.recvs.append( str( item.getAttribute("android:name") ) )
						for child in item.getElementsByTagName('action'):
							self.recvsaction[str( item.getAttribute("android:name") )] = (str( child.getAttribute("android:name") ))

					for item in xml[i].getElementsByTagName('activity') + xml[i].getElementsByTagName('activity-alias'):
						activity = str( item.getAttribute("android:name") )
						self.activities[activity] = {}
						self.activities[activity]["actions"] = list()
			
						for child in item.getElementsByTagName('action'):
							self.activities[activity]["actions"].append(str(child.getAttribute("android:name")))

					for activity in self.activities:
						for action in self.activities[activity]["actions"]:
							if action == 'android.intent.action.MAIN':
								self.mainActivity = activity
					error = False

					break

			if (error == False):
				return 1
			else:
				return 0

		except:
			return 0

    def getEnfperm(self):
		return self.enfperm

    def getMainActivity(self):
		return self.mainActivity

    def getActivities(self):
		return self.activities

    def getRecvActions(self):
		return self.recvsaction

    def getPackage(self):
		#One application has only one package name
		return self.packageNames[0]
 
    def getHashes(self, block_size=2**8):
		"""
		Calculate MD5,SHA-1, SHA-256
		hashes of APK input file
		"""

		md5 = hashlib.md5()
		sha1 = hashlib.sha1()
		sha256 = hashlib.sha256()
		f = open(self.filename, 'rb')
		while True:
			data = f.read(block_size)
			if not data:
				break
			md5.update(data)
			sha1.update(data)
			sha256.update(data)
		return [md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()]
 
def decode(s, encodings=('ascii', 'utf8', 'latin1')):
    for encoding in encodings:
	try:
	    return s.decode(encoding)
	except UnicodeDecodeError:
	    pass
    return s.decode('ascii', 'ignore')

def getTags(tagParam):
    """
    Retrieve the tag names
    """

    tagsFound = []
    for tag in tags.keys():
        if tagParam & tag != 0:
            tagsFound.append(tags[tag])
    return tagsFound

def hexToStr(hexStr):
    """
    Convert a string hex byte values into a byte string
    """

    bytes = []
    hexStr = ''.join(hexStr.split(" "))
    for i in range(0, len(hexStr), 2):
	bytes.append(chr(int(hexStr[i:i+2], 16)))
    return unicode(''.join( bytes ), errors='replace')


def interruptHandler(signum, frame):
    """ 
	Raise interrupt for the blocking call 'logcatInput = sys.stdin.readline()'
	
	"""
    raise KeyboardInterrupt	

def begin(file,dura):		    
	duration = dura

	#Duration given?


	apkName = file#sys.argv[1]

	#APK existing?
	if os.path.isfile(apkName) == False:
	    print("File %s not found")
		#sys.exit(1)
	application = Application(apkName)
	ret = application.processAPK()

	#Error during the APK processing?
	if (ret == 0):
		print("Failed to analyze the APK. Terminate the analysis.")
		sys.exit(1)

	activities = application.getActivities()
	mainActivity = application.getMainActivity()
	packageName = application.getPackage()

	recvsaction = application.getRecvActions()
	enfperm = application.getEnfperm()

	#Get the hashes
	hashes = application.getHashes()

	#curses.setupterm()
	#sys.stdout.write(curses.tigetstr("clear"))
	#sys.stdout.flush()
	call(['adb', 'logcat', '-c'])

	print u" ____                        __  ____"
	print u"/\  _`\               __    /\ \/\  _`\\"
	print u"\ \ \/\ \  _ __  ___ /\_\   \_\ \ \ \L\ \   ___   __  _"  
	print u" \ \ \ \ \/\`'__\ __`\/\ \  /'_` \ \  _ <' / __`\/\ \/'\\" 
	print u"  \ \ \_\ \ \ \/\ \L\ \ \ \/\ \L\ \ \ \L\ \\ \L\ \/>  </"
	print u"   \ \____/\ \_\ \____/\ \_\ \___,_\ \____/ \____//\_/\_\\"
	print u"    \/___/  \/_/\/___/  \/_/\/__,_ /\/___/ \/___/ \//\/_/"

	#No Main acitvity found? Return an error
	if mainActivity == None:
		print("No activity to start. Terminate the analysis.")
		sys.exit(1)

	#No packages identified? Return an error
	if packageName == None:
		print("No package found. Terminate the analysis.")
		sys.exit(1)
	mypath=os.path.dirname(os.path.realpath(__file__))
	#Execute the application

	retheart = call(['monkeyrunner','monkeyrunner.py', 'heart.apk', "com.qiye.txz.heartbeatdetect", "com.qiye.txz.heartbeatdetect.MainActivity"], stderr=PIPE, cwd=os.path.dirname(os.path.realpath(__file__)))
	ret = call(['monkeyrunner', 'monkeyrunner.py', apkName, packageName, mainActivity], stderr=PIPE, cwd=os.path.dirname(os.path.realpath(__file__)))#
	#ret = os.system(monkeyrunnerpath+"monkeyrunner.bat "+mypath+"\\monkeyrunner.py"+" "+apkName+" "+packageName+" "+mainActivity)#
	if (retheart == 1):
		print("Failed to execute the heart.")
		sys.exit(1)
	if (ret == 1):
		print("Failed to execute the application.")
		sys.exit(1)

	#print("Starting the activity %s..." % mainActivity)

	#By default the application has not started
	applicationStarted = 0
	stringApplicationStarted = "Start proc"
	stringpackageName=" %s" % packageName

	#Open the adb logcat
	adb = Popen(["adb", "logcat", "360Qiyemono:D", "dalvikvm:W", "ActivityManager:I","*:S"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)

	#Wait for the application to start
	while 1:
		try:
			logcatInput = adb.stdout.readline()
			if not logcatInput:
				raise Exception("We have lost the connection with ADB.")
			#Application started?
			if (stringApplicationStarted in logcatInput):
				if(stringpackageName in logcatInput):
					applicationStarted = 1
					break
		except:
			break

	if (applicationStarted == 0):
		print("Analysis has not been done.")
		#os.kill(adb.pid)
		#, signal.SIGTERM)
		sys.exit(1)
		#Kill ADB, otherwise it will never terminate

	print("Application started")
	#print("Analyzing the application during %s seconds..." % (duration if (duration !=0) else "infinite time"))

	#count = CountingThread()
	#count.start()

	timeStamp = time.time()
	if duration:
	    #signal.signal(signal.SIGALRM, interruptHandler)
	    #signal.alarm(duration)
		print "hello"
	#Collect DroidBox logs
	breaksign=0
	if os.path.exists(mypath+'/log.txt'):
		os.system("del "+mypath+"/log.txt")
	fp=open(mypath+"/log.txt",'a')
	while 1:
	    try:
			logcatInput = adb.stdout.readline()
			if not logcatInput:
				raise Exception("We have lost the connection with ADB.")
			boxlog = logcatInput.split('360Qiyemon-apimonitor-'+packageName+':')
			if len(boxlog) > 1:
				fp.writelines(logcatInput)
			if not len(boxlog)>1:
				boxlog = logcatInput.split('360Qiyemon-apimonitor-heartbeatsignal:')
			#boxlog1="{\"result\":\"java.lang.String->compareToIgnoreCase\",\"this\":\"\",\"PID\":2187,\"TID\":2187,\"UID\":10028,\"Method\":\"java.lang.StringBuilder->toString\",\"Funtion\":\"toString\",\"Time\":1531276365049}\r\r\n"
			if len(boxlog) > 1:
				try:
					load = json.loads(decode(boxlog[1]))
					#parameter=load['Parameters']['path']
					# DexClassLoader
					if not load.has_key('Function'):
						continue
					if load['Function']=='open':
						print "open"
						breaksign=0
						#load.has('system')
					elif load['Function']=='DexClassLoader':
						#load['DexClassLoader']['type'] = 'dexload'
						dexclass[time.time() - timeStamp] = "dexload"#load['DexClassLoader']
						#count.increaseCount()
						breaksign=0
					# service started
					elif load['Function']==('ServiceStart'):
						#load['ServiceStart']['type'] = 'service'
						servicestart[time.time() - timeStamp] = "service"#load['ServiceStart']
						#count.increaseCount()
						breaksign=0
					# received data from net
					elif load['Function']=='RecvNet':   
						#host = load['RecvNet']['srchost']
						#port = load['RecvNet']['srcport']

						#recvnet[time.time() - timeStamp] = recvdata = {'type': 'net read', 'host': host, 'port': port, 'data': load['RecvNet']['data']}
						#count.increaseCount()
						print "RecvNet"
					# fdaccess
					elif load['Function']=='FdAccess':
						#accessedfiles[load['FdAccess']['id']] = hexToStr(load['FdAccess']['path'])
						print "FdAccess"
						breaksign=0
					# file read or write     
					elif load['Function']=='FileRW':
						#load['FileRW']['path'] = accessedfiles[load['FileRW']['id']]
						#elif load['FileRW']['operation'] == 'write':
							#load['FileRW']['type'] = 'file write'
						#else:
							#load['FileRW']['type'] = 'file read'

						fdaccess[time.time()-timeStamp] ="FileRW"# load['FileRW']
						#count.increaseCount()
						breaksign=0
					# opened network connection log
					elif load['Function']=='OpenNet':
						opennet[time.time()-timeStamp] = "OpenNet"#load['OpenNet']
						#count.increaseCount()
						breaksign=0
					# closed socket
					elif load['Function']=='CloseNet':
						closenet[time.time()-timeStamp] = "CloseNet"#load['CloseNet']
						#count.increaseCount()
						breaksign=0
					# outgoing network activity log
					elif load['Function']=='SendNet':
						#load['SendNet']['type'] = 'net write'
						sendnet[time.time()-timeStamp] = "SendNet"#load['SendNet']
						#count.increaseCount()                                          
						breaksign=0
					# data leak log
					elif load['Function']=='DataLeak':
						'''
						my_time = time.time()-timeStamp
						load['DataLeak']['type'] = 'leak'
						load['DataLeak']['tag'] = getTags(int(load['DataLeak']['tag'], 16))
						dataleaks[my_time] = load['DataLeak']
						count.increaseCount()

						elif load['DataLeak']['sink'] == 'Network':
							load['DataLeak']['type'] = 'net write'
							sendnet[my_time] = load['DataLeak']
							count.increaseCount()

						elif load['DataLeak']['sink'] == 'File':	
							load['DataLeak']['path'] = accessedfiles[load['DataLeak']['id']]
							if load['DataLeak']['operation'] == 'write':
								load['DataLeak']['type'] = 'file write'
							else:
								load['DataLeak']['type'] = 'file read'

							fdaccess[my_time] = load['DataLeak']
							count.increaseCount()
						elif load['DataLeak']['sink'] == 'SMS':
							load['DataLeak']['type'] = 'sms'
							sendsms[my_time] = load['DataLeak']
							count.increaseCount()'''
						print "DataLeak"
						breaksign=0
					# sent sms log
					elif load['Function']=='SendSMS':
						#load['SendSMS']['type'] = 'sms'
						sendsms[time.time()-timeStamp] = "sms"#load['SendSMS']
						#count.increaseCount()
						breaksign=0
					# phone call log
					elif load['Function']=='PhoneCall':
						#load['PhoneCall']['type'] = 'call'
						phonecalls[time.time()-timeStamp] = 'call'#load['PhoneCall']
						#count.increaseCount()
						breaksign=0
					# crypto api usage log
					elif load['Function']=='CryptoUsage':
						#load['CryptoUsage']['type'] = 'crypto'                                                                   
						cryptousage[time.time()-timeStamp] = 'crpto'#load['CryptoUsage']
						#count.increaseCount()
						breaksign=0
					elif load['Function']=='heartbeat':
						breaksign+=1
						if breaksign==2000:
							break
						print "continue"
					else:
						breaksign=0
				except ValueError:
					print ValueError
					#break
					pass

	    except:
			break
			pass
	fp.close()
	#Kill ADB, otherwise it will never terminate
	#os.kill(adb.pid)
	#os.popen('taskkill.exe /pid:'+adb.pid)
	#Done? Store the objects in a dictionary, transform it in a JSON object and return it
	output = dict()

	#Sort the items by their key
	output["dexclass"] = dexclass
	output["servicestart"] = servicestart

	output["recvnet"] = recvnet
	output["opennet"] = opennet
	output["sendnet"] = sendnet
	output["closenet"] = closenet

	output["accessedfiles"] = accessedfiles
	output["dataleaks"] = dataleaks

	output["fdaccess"] = fdaccess
	output["sendsms"] = sendsms
	output["phonecalls"] = phonecalls
	output["cryptousage"] = cryptousage

	output["recvsaction"] = recvsaction
	output["enfperm"] = enfperm

	output["hashes"] = hashes
	output["apkName"] = apkName
	pathtemp = sys.path[0]
	os.chdir(pathtemp)
	f=open(mypath+'/log/droidboxlog_'+time.strftime("%Y-%m-%d-%H%M%S", time.localtime())+'.json','w') #+ time.strftime('%H:%M_%Y%m%d')
	f.write(json.dumps(output,sort_keys=True, indent=4, separators=(',', ':')))
	f.close()


	print(json.dumps(output))
	#log=Popen(['adb','logcat','360Qiyemon-apimonitor-'+packageName])
	#log=Popen(["adb", "logcat", "360Qiyemon-apimonitor-"+packageName,"*:S"])
	
	#print log

	
	#sys.exit(0)
def devicesfind():
	ipport=[]
	find = False
	ret = Popen(['adb','devices'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
	logcatInput="ture"
	while logcatInput!="":
		logcatInput = ret.stdout.readline()
		if not logcatInput:
			for i in range(0,len(ipport)):
				if len(workavdip)<i:
					freeavdip.append(ipport[i])
					continue
				for j in workavdip:
					if  ipport[i]==j:
						find = True
						break
					find=False
				if find==False:
					freeavdip.append(ipport[i])
				find=False
			return 
			#raise Exception("We have lost the connection with ADB.")
		boxlog = logcatInput.split('emulator-')
		
		if len(boxlog) > 1:
			ipport.append(boxlog[1].split('\tdevice')[0])
			#if "\tdevice\r\n"
			#return True
def startavdfinished():
	applicationStarted = 0
	stringApplicationStarted = "Start proc com.android.systemui"
	stringpackageName="Start proc com.google.android.googlequicksearchbox"

	#Open the adb logcat
	adb = Popen(["adb", "logcat", "dalvikvm:W", "ActivityManager:I","*:S"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)

	#Wait for the application to start
	while 1:
		try:
			logcatInput = adb.stdout.readline()
			if not logcatInput:
				raise Exception("We have lost the connection with ADB.")
			#Application started?
			if (stringApplicationStarted in logcatInput):
				#if(stringpackageName in logcatInput):
				#applicationStarted = 1
				#os.kill(adb.pid)
				#time.sleep(2)
				break
		except:
			print "avdstarterror"
			sys.exit(0)	

def main():
	#emulator -avd testavd -writable-system -partition-size 200 -no-snapshot-save
	#-no-snapshot-load
	workavdip.append("5554")
	workavdip.append("5556")
	workavdip.append("5558")
	#del workavdip[0]
	devicesfind()
	if len(freeavdip)==0:
		ret = Popen([emulatorpath+'emulator','-avd', 'testavd','-writable-system','-partition-size','2000','-no-snapshot-save'])#'system-writable'
		devicesfind()
		startavdfinished()
	#print ret
	path = os.path.dirname(os.path.realpath(__file__)) #文件夹目录
	files= os.listdir(path+"/file") #得到文件夹下的所有文件名称
	s = []
	for file in files:
		#遍历文件夹
		if not os.path.isdir(file):
			begin(path+"/file/"+file,0)
if __name__ == "__main__":
	main()
