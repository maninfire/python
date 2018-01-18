sa="KanXueCrackMe2017"
sb="EDAHE450C741GH441E11BH84"
mid=334476251944397096847543189896
aplb="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
apls="abcdefghijklmnopqrstuvwxyz"
sa=sa[::-1]
print sa
sb=sb[::-1]
print sb
print mid
def str_to_sixtytwo():
    l=[]
    for i in range(len(sa)):
        if(ord(sa[i])>=ord('0') and ord(sa[i])<=ord('9')):
            l.append(ord(sa[i])-ord('0'))
        if(ord(sa[i])>=ord('a') and ord(sa[i])<=ord('z')):
            l.append(ord(sa[i])-ord('='))
        if(ord(sa[i])>=ord('A') and ord(sa[i])<=ord('Z')):
            l.append(ord(sa[i])-ord('7'))

    n=0
    
    for i in range(len(l)):
        n=n*62
        n=n+l[i]

    return n
def str_to_eighteen():
    l=[]
    for i in range(len(sb)):
        if(ord(sb[i])>=ord('0') and ord(sb[i])<=ord('9')):
            l.append(ord(sb[i])-ord('0'))
        if(ord(sb[i])>=ord('A') and ord(sb[i])<=ord('H')):
            l.append(ord(sb[i])-ord('7'))
    n=0

    for i in range(len(l)):
        n=n*18
        n=n+l[i]
    return n

def len_long(midtemp):
    len=0    
    while (midtemp>0):
        midtemp=midtemp/10
        len=len+1
    return len
def long_to_list(midtemp):
    num18=[]
    len=lenlong(midtemp) 
    for i in range(0,len,2):
        if(i==0):
            midtemp=mid%100
        else:
            midtemp=mid/(10**i)%100
        num18.append(midtemp)
    return num18
def eighteen_to_list(midtemp):
    temp=1
    n=[]
    len=len_long(midtemp) 
    while(midtemp>0):
        temp=midtemp%18
        n.append(temp)
        midtemp=midtemp/18
    return n
    
def sixtytwo_to_list(midtemp):
    temp=1
    n=[]
    len=lenlong(midtemp) 
    while(midtemp>0):
        temp=midtemp%62
        n.append(temp)
        midtemp=midtemp/62
    return n

def list_to_str(arg):
    strn=""
    for i in range(len(arg)):
        if(arg[i]<10 and arg[i]>=0):
            strn=strn+str(arg[i])
        if(arg[i]>=9 and arg[i]<36):
            #ABCD
            n=arg[i]-9
            strn=strn+aplb[n-1]
        if(arg[i]>=36 and arg[i]<62):
            #abcd
            n=arg[i]-36
            strn=strn+apls[n-1]
    return strn
print ""
etl= eighteen_to_list(mid)
strshow=list_to_str(etl)
print "%s"%strshow
