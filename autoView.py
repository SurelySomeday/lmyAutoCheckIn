#!/usr/bin/python3
import threading
import multiprocessing
import hashlib
import hmac
import datetime
import time
import os
import requests

noticeFile = False
noticeVideo = False;
md5 = "9579D1CB25BADE7F8A3EB479DD0A2AC3";
location = {"12305":{"lat":"33.548733", "lng":"119.033165"},"12407":{"lat":"33.553117", "lng":"119.031301"},
            "yf514":{"lat":"33.554198","lng":"119.030223"}, "empty":{"lat":"", "lng":""}}

#登录
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

#获取所有的课程id
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

#获取所有课程信息
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

#获得所有的资源id
def getFileIds(userInfo,clazzId):
    li = list()
    try:
        getFileIdsUrl = "http://api.mosoteach.cn/mssvc/index.php/ccfile/index"
        headers = {"Accept-Encoding":"gzip;q=0.7,*;q=0.7", "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 7.1.1; MX6 Build/NMF26O)",
                     "Date":"","X-device-code":"8faffe60_ebd5_4890_a532_c68523f6daae", "X-mssvc-signature":"",
                       "X-mssvc-access-id":userInfo['access_id'],"X-app-id": "MTANDROID", "X-app-version":"3.1.2","X-mssvc-sec-ts":userInfo['last_sec_update_ts_s'],
        "Content-Type":"application/x-www-form-urlencoded; charset=UTF-8"}
        getFileIdsFormdata={ "clazz_course_id":clazzId, "role_id":"2"}
        headers["Date"] = getDate()
        headers["X-mssvc-signature"] = getSignature(getFileIdsUrl, userInfo['user_id'], getDate(), userInfo['access_secret'], getFileIdsFormdata)
        r = requests.post(getFileIdsUrl, headers=headers, data=getFileIdsFormdata);
        json = r.json()
        for data in json['data']:
            if data['view_status']=='N':
                li.append(data['id'])
    except:
        print("getFileIds wrong!")
    finally:
        return li

#获取资源地址(查看资源)
def getFileUrl(userInfo,fileId):
    try:
        getFileURl="http://api.mosoteach.cn/mssvc/index.php/ccfile/get_file_url"
        headers = {"Accept-Encoding":"gzip;q=0.7,*;q=0.7", "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 7.1.1; MX6 Build/NMF26O)",
                     "Date":"","X-device-code":"8faffe60_ebd5_4890_a532_c68523f6daae", "X-mssvc-signature":"",
                       "X-mssvc-access-id":userInfo['access_id'],"X-app-id": "MTANDROID", "X-app-version":"3.1.2","X-mssvc-sec-ts":userInfo['last_sec_update_ts_s'],
        "Content-Type":"application/x-www-form-urlencoded; charset=UTF-8"}
        getFileFormdata={ "file_id":fileId, "role_id":"2","type":"view"}
        headers["Date"] = getDate()
        headers["X-mssvc-signature"] = getSignature(getFileURl, userInfo['user_id'], getDate(), userInfo['access_secret'], getFileFormdata)
        r = requests.post(getFileURl, headers=headers, data=getFileFormdata);
    except:
        print("getFileUrl wrong!")

#获取视频资源信息
def getVideoInfo(userInfo,clazzId):
    li = list()
    try:
        getFileIdsUrl = "http://api.mosoteach.cn/mssvc/index.php/ccfile/index"
        headers = {"Accept-Encoding":"gzip;q=0.7,*;q=0.7", "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 7.1.1; MX6 Build/NMF26O)",
                     "Date":"","X-device-code":"8faffe60_ebd5_4890_a532_c68523f6daae", "X-mssvc-signature":"",
                       "X-mssvc-access-id":userInfo['access_id'],"X-app-id": "MTANDROID", "X-app-version":"3.1.2","X-mssvc-sec-ts":userInfo['last_sec_update_ts_s'],
        "Content-Type":"application/x-www-form-urlencoded; charset=UTF-8"}
        getFileIdsFormdata={ "clazz_course_id":clazzId, "role_id":"2"}
        headers["Date"] = getDate()
        headers["X-mssvc-signature"] = getSignature(getFileIdsUrl, userInfo['user_id'], getDate(), userInfo['access_secret'], getFileIdsFormdata)
        r = requests.post(getFileIdsUrl, headers=headers, data=getFileIdsFormdata);
        json = r.json()
        for data in json['data']:
            if data['type_code']=='0205' and  data['obtain_score']==-1:
                li.append({'clazz_course_id':data['clazz_course_id'],'res_id':data['id'],'duration':data['meta_duration']})
    except:
        print("getVideoInfo wrong!")
    finally:
        return li

#查看视频资源
def watchVideo(userInfo,videoInfo):
    try:
        url = "http://api.mosoteach.cn/mssvc/index.php/cc_record/save_res_video_record"
        headers = {"Accept-Encoding":"gzip;q=0.7,*;q=0.7", "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 7.1.1; MX6 Build/NMF26O)",
                     "Date":"","X-device-code":"8faffe60_ebd5_4890_a532_c68523f6daae", "X-mssvc-signature":"",
                       "X-mssvc-access-id":userInfo['access_id'],"X-app-id": "MTANDROID", "X-app-version":"3.1.2","X-mssvc-sec-ts":userInfo['last_sec_update_ts_s'],
        "Content-Type":"application/x-www-form-urlencoded; charset=UTF-8"}
        saveWatchtoFormdata={ "clazz_course_id":videoInfo['clazz_course_id'],
        "current_watch_to":videoInfo['duration'],"duration":videoInfo['duration'],"res_id":videoInfo['res_id'],"watch_to":videoInfo['duration']}
        headers["Date"] = getDate()
        headers["X-mssvc-signature"] = getSignature(url, userInfo['user_id'], getDate(), userInfo['access_secret'], saveWatchtoFormdata)
        r = requests.post(url, headers=headers, data=saveWatchtoFormdata)
    except:
        print("watchVideo wrong!")

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

#开始查看视频资源
def nowWatchVideo(userInfo, clazz):
    global noticeVideo
    videos = getVideoInfo(userInfo, clazz['clazz_id'])
    if len(videos)==0:
        if noticeVideo==False:
            noticeVideo=True
            print("没有视频资源需要查看   ")
        return
    print("正在查看"+str(len(videos))+"个视频资源")
    for video in videos:
        watchVideo(userInfo,video)
    print("所有视频资源查看完毕!")

#查看文件资源
def nowGetFile(userInfo, clazz):
    global noticeFile
    ids = getFileIds(userInfo, clazz['clazz_id'])
    if len(ids)==0:
        if noticeFile==False:
            noticeFile=True
            print("没有文件资源需要查看   ")
        return
    print("正在查看"+str(len(ids))+"个文件资源")
    for fileId in ids:
        getFileUrl(userInfo,fileId)
    print("所有文件资源查看完毕!")

#启动查看资源  
def startCheckIn(name, pwd):
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
        print("用户名或密码错误！")
        return
    else:
        userInfo=loginInfo['user']
        print(userInfo['full_name']+" 登陆成功!")
        print("运行中........")
        clazzInfo=getAllClazzInfo(userInfo)['data']
        clazzList=list()
        for clazz in clazzInfo:
            clazzList.append({'clazz_id':clazz['id'],'clazz_name':clazz['course_name'], 'flag':0})
        while True:
            for clazz in clazzList:
                if clazz['flag']>0:
                    clazz['flag']-=1;
                threading.Thread(target=nowGetFile,args=(userInfo, clazz)).start()
                threading.Thread(target=nowWatchVideo,args=(userInfo, clazz)).start()
            time.sleep(0.5)


name=input("账号：")
pwd=input("密码：")
startCheckIn(name,pwd)
