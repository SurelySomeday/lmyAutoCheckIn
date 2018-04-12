import requests
import threading
import hashlib
import hmac
import datetime
import time
import sys
import socket
from msgapp import models

flag = False
users = dict()
md5 = "9579D1CB25BADE7F8A3EB479DD0A2AC3";
location = {"12305":{"lat":"33.548733", "lng":"119.033165"},"12407":{"lat":"33.553117", "lng":"119.031301"},
            "yf514":{"lat":"33.554198","lng":"119.030223"}, "empty":{"lat":"", "lng":""}}


def login(name, pwd):
    try:
        loginUrl = "http://api.mosoteach.cn/mssvc/index.php/passport/login"
        headers = {"Accept-Encoding":"gzip;q=0.7,*;q=0.7", "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 7.1.1; MX6 Build/NMF26O)",
         "Accept-Encoding": "gzip, deflate, br", "Date":"", "X-mssvc-signature":"",
           "X-app-id": "MTANDROID", "X-app-version":"3.1.2", "Content-Type":"application/x-www-form-urlencoded; charset=UTF-8"}
        loginFormdata = {"account_name":"", "app_id":"MTANDROID", "app_version_name":"3.1.2",
                 "app_version_number":"76", "device_code":"39285fe4_d165_46d6_a716_d017dd1ad4a4",
                 "device_pn_code":"39285fe4_d165_46d6_a716_d017dd1ad4a4", "device_type":"ANDROID","dpr":"3.0",
                 "public_key":"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCmQVJFfoyV3ewxIjlCambLMFfJLlToOhoSV31qVieZYwz6kI3JywW2OEORSqZn9w1UkSkCMRjI5szT1fKe8XA93M8ZjKsnRrFt4U7VRyWpBYrVKiLuY7mukU7wumoEgi6ILTT1BECAbBQFF21vnpJnkfPwzKiAV825FnzRCINanQIDAQAB",
                 "system_version":"7.1.1", "user_pwd":""}
        loginFormdata["account_name"] = name
        loginFormdata["user_pwd"] = pwd
        headers["Date"] = getDate()
        headers["X-mssvc-signature"] = getLoginSignature(loginUrl, getDate(), loginFormdata)
        r = requests.post(loginUrl, headers=headers, data=loginFormdata);
        return r.json()
    except:
        print("login wrong!")
        return None

def getAllClazzId(userInfo):
    try:
        getClassIdURl="http://api.mosoteach.cn/mssvc/index.php/ccmsg/list_pn"
        headers = {"Accept-Encoding":"gzip;q=0.7,*;q=0.7", "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 7.1.1; MX6 Build/NMF26O)",
                 "Date":"","X-device-code":"8faffe60_ebd5_4890_a532_c68523f6daae", "X-mssvc-signature":"",
                   "X-mssvc-access-id":userInfo['access_id'],"X-app-id": "MTANDROID", "X-app-version":"3.1.2","X-mssvc-sec-ts":userInfo['last_sec_update_ts_s'],
        "Content-Type":"application/x-www-form-urlencoded; charset=UTF-8"}
        getClassIdFormdata = { "app_id":"MTANDROID","device_pn_code":"39285fe4_d165_46d6_a716_d017dd1ad4a4"}
        headers["Date"] = getDate()
        headers["X-mssvc-signature"] = getSignature(getClassIdURl, userInfo['user_id'], getDate(), userInfo['access_secret'], getClassIdFormdata)
        r = requests.post(getClassIdURl, headers=headers, data=getClassIdFormdata);
        json=r.json()
        return json['data']['details']
    except:
        print("getAllClazzId wrong")
        return None

def getAllClazzInfo(userInfo):
    try:
        getAllClazzUrl = "http://api.mosoteach.cn/mssvc/index.php/clazzcourse/my_cc"
        headers = {"Accept-Encoding":"gzip;q=0.7,*;q=0.7", "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 7.1.1; MX6 Build/NMF26O)",
                 "Date":"","X-device-code":"8faffe60_ebd5_4890_a532_c68523f6daae", "X-mssvc-signature":"",
                   "X-mssvc-access-id":userInfo['access_id'],"X-app-id": "MTANDROID", "X-app-version":"3.1.2","X-mssvc-sec-ts":userInfo['last_sec_update_ts_s'],
        "Content-Type":"application/x-www-form-urlencoded; charset=UTF-8"}
        getAllClazzFormdata={"dpr":"2"}
        headers["Date"] = getDate()
        headers["X-mssvc-signature"] = getSignature(getAllClazzUrl, userInfo['user_id'], getDate(), userInfo['access_secret'], getAllClazzFormdata)
        r = requests.post(getAllClazzUrl, headers=headers, data=getAllClazzFormdata);
        return r.json()
    except:
        print("getAllClazzInfo wrong!")
        return None
     
    
def checkIsOpen(userInfo, clazzId):
    try:
        checkOpenUrl="http://api.mosoteach.cn/mssvc/index.php/checkin/current_open"
        headers = {"Accept-Encoding":"gzip;q=0.7,*;q=0.7", "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 7.1.1; MX6 Build/NMF26O)",
                 "Date":"","X-device-code":"39285fe4_d165_46d6_a716_d017dd1ad4a4", "X-mssvc-signature":"",
                   "X-mssvc-access-id":userInfo['access_id'],"X-app-id": "MTANDROID", "X-app-version":"3.1.2","X-mssvc-sec-ts":userInfo['last_sec_update_ts_s'],
        "Content-Type":"application/x-www-form-urlencoded; charset=UTF-8"}
        checkOpenFormdata = { "clazz_course_id":clazzId}
        headers["Date"] = getDate()
        headers["X-mssvc-signature"] = getSignature(checkOpenUrl, userInfo['user_id'], getDate(), userInfo['access_secret'], checkOpenFormdata)
        r = requests.post(checkOpenUrl, headers=headers, data=checkOpenFormdata);
        return r.json()
    except:
        print("checkIsOpen wrong!")
        return None
def checkIn(userInfo, checkId, location):
    try:
        checkInUrl="http://checkin.mosoteach.cn:19527/checkin"
        headers = {"Accept-Encoding":"gzip;q=0.7,*;q=0.7", "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 7.1.1; MX6 Build/NMF26O)",
                 "Date":"","X-device-code":"39285fe4_d165_46d6_a716_d017dd1ad4a4", "X-mssvc-signature":"",
                   "X-mssvc-access-id":userInfo['access_id'],"X-app-id": "MTANDROID", "X-app-version":"3.1.2","X-mssvc-sec-ts":userInfo['last_sec_update_ts_s'],
        "Content-Type":"application/x-www-form-urlencoded; charset=UTF-8"}
        checkOpenFormdata = { "checkin_id":checkId, "report_pos_flag":"Y", "lat":location['lat'], "lng":location['lng']}
        headers["Date"] = getDate()
        headers["X-mssvc-signature"] = getSignature(checkInUrl, userInfo['user_id'], getDate(), userInfo['access_secret'], None)
        r = requests.post(checkInUrl, headers=headers, data=checkOpenFormdata);
        return r.json()
    except:
        print("checkIn wrong!")
        return None

def getDate():
    times=datetime.datetime.now() + datetime.timedelta(hours=-8)
    formatDate=times.strftime("%a, %d %b %Y-%m-%d %H:%M:%S GMT+00:00")
    return formatDate

def getMD5(data):
    md5=hashlib.md5()
    md5.update(data.encode('utf-8'))
    return md5.hexdigest()


def getMacSHA1(data1, data2):
    hmacSha1 = hmac.new(data1.encode('utf-8'),data2.encode('utf-8'),hashlib.sha1)
    return hmacSha1.hexdigest()

def getLoginSignature(url, gmtTime, formdata):
    global md5
    str1="%s|%s"%(url,gmtTime)
    for name in formdata:
        str1=str1+"|%s=%s"%(name, formdata[name])
    return getMacSHA1(md5,str1)

def getSignature(url, user_id, gmtTime, access_secret, formdata):
    if formdata==None or len(formdata)==0:
        str1="%s|%s|%s"%(url, user_id, gmtTime)
        return getMacSHA1(access_secret, str1)
    else:
        str1=""
        for name in formdata:
            str1=str1+"%s=%s|"%(name, formdata[name])
        str1=str1[0:len(str1)-1]
        str1="%s|%s|%s|%s"%(url, user_id.upper(), gmtTime, getMD5(str1).upper())
        return getMacSHA1(access_secret, str1)
        
def startCheckIn(name, pwd):
    global users
    global flag
    dt=datetime.datetime.now()
    day=dt.weekday()
    classRom=""

    if day==2:
        classRom="yf514"
    elif day==3:
        classRom="12407"
    elif day==4:
        classRom="12305"
    else:
        classRom="empty"
    
    classRom="empty"
    loginInfo=login(name,pwd)
    if loginInfo==None:
        print("登陆失败")
    elif loginInfo['result_code']==1007:
        users.pop(name)
        delUser(name)
        print("用户名或密码错误！")
        return
    else:
        userInfo=loginInfo['user']
        print(userInfo['full_name']+" 登陆成功!")
        clazzInfo=getAllClazzInfo(userInfo)['data']
        clazzList=list()
        for clazz in clazzInfo:
            clazzList.append({'clazz_id':clazz['id'],'clazz_name':clazz['course_name'], 'flag':0})
        count=0
        while(True):
            if flag==False:
                return
            if name not in users.keys():
                return
            for clazz in clazzList:
                if clazz['flag']>0:
                    clazz['flag']-=1;
                msg=checkIsOpen(userInfo, clazz['clazz_id'])
                if msg!=None and msg['result_msg']=="OK" and clazz['flag']==0:
                    checkInMsg=checkIn(userInfo, msg['id'], location[classRom])
                    if checkInMsg!=None and checkInMsg['result_code'] == 2409:
                        print(datetime.datetime.today().strftime("%Y/%m/%d %H:%M:%S")+" "+clazz['clazz_name']+" 重复签到!")
                        clazz['flag']=10;
                    elif checkInMsg!=None and checkInMsg['result_msg']=='OK':
                        clazz['flag']=10;
                        models.CheckInfo.objects.create(fullname=userInfo['full_name'],username=name,coursename=clazz['clazz_name'], date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                        print(datetime.datetime.today().strftime("%Y/%m/%d %H:%M:%S")+" "+clazz['clazz_name']+" 签到成功!")
            time.sleep(1)
            count=count+1;
def begin():
    global flag
    global users
    flag = True;
    user_list = models.UserInfo.objects.all()
    for line in user_list:
        users[line.username] = line.password
    if len(users)!=0:
        for k in users:
            threading.Thread(target=startCheckIn, args=(k,users[k])).start()

def refresh():
    global flag
    global users
    flag = True
    tmpUsers=dict()
    user_list = models.UserInfo.objects.all()
    for line in user_list:
        tmpUsers[line.username] = line.password
    if len(tmpUsers)!=0:
        for k in tmpUsers:
            if k not in users.keys():
                threading.Thread(target=startCheckIn, args=(k,tmpUsers[k])).start()
    users = tmpUsers

def destory():
    global flag
    flag = False
    
def startListen():
    global flag
    sk = socket.socket()  # 创建socket对象
    sk.bind(("localhost", 8888))  # 绑定端口,“127.0.0.1”代表本机地址，8888为设置链接的端口地址
    sk.listen(5)  # 设置监听，最多可有5个客户端进行排队
    while True:
        conn, addr = sk.accept()  # 阻塞状态，被动等待客户端的连接
        accept_data = conn.recv(1024)  # conn.recv()接收客户端的内容，接收到的是bytes类型数据，
        recvmsg = str(accept_data, encoding="utf8")  # str(data,encoding="utf8")用“utf8”进行解码
        msg = ''
        if recvmsg=='停止签到':
            destory()
            msg = 'stop'
        elif recvmsg=='开始签到':
            begin()
            msg = 'running'
        elif recvmsg=='check':
            if flag==True:
                msg = 'running'
            else:
                 msg = 'stop'
        else:
            refresh()
        conn.sendall(bytes(msg, encoding="utf8"))
        conn.close()
