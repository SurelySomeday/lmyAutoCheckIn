from django.shortcuts import render
from datetime import datetime
import socket
from msgapp import models

# Create your views here.
def showHome(request):
    datalist = dict()
    datalist['data']=list()
    datalist['checkInfo']=list()
    if request.method == 'POST':
        way = request.POST.get('way', None)
        if way == 'addUser':
            username = request.POST.get('username', None)
            password = request.POST.get('password', None)
            msg=addUser(username, password)
            datalist['addMsg'] = msg
        elif way == 'delUser':
            delUsername = request.POST.get('delUsername', None)
            msg=delUser(delUsername)
            datalist['delMsg'] = msg
        elif way == '开始签到':
            sendMsg(way)
        elif way == '停止签到':
            sendMsg(way)
        elif way == 'clearDb':
            clearDb()
    msg = sendMsg('check')
    if msg=='running':
        datalist['operate'] = "停止签到"
    elif msg == 'stop':
        datalist['operate'] = "开始签到"
    user_list = models.UserInfo.objects.all()
    for line in user_list:
        d = {"username": line.username, "time": line.date}
        datalist['data'].append(d)
    info_list = models.CheckInfo.objects.all()
    for line in info_list:
        d = {"username": line.username, "fullname": line.fullname,"coursename": line.coursename, "time": line.date}
        datalist['checkInfo'].append(d)

    return render(request, "MsgSingleWeb.html", {"data": datalist})

def delUser(uname):
    msg=''
    queryUser = models.UserInfo.objects.filter(username=uname)
    if queryUser.exists():
        queryUser.delete()
        msg = '删除成功！'
    else:
        msg = '用户不存在！'
    sendMsg(msg)
    return msg

def addUser(uname, pwd):
    msg=''
    time=datetime.now()
    queryUser = models.UserInfo.objects.filter(username=uname)
    if queryUser.exists():
        msg = '用户已经存在!'
    else:
        msg = '添加成功！' 
        models.UserInfo.objects.create(username=uname,password=pwd, date=time.strftime("%Y-%m-%d %H:%M:%S"))
    sendMsg(msg)
    return msg

def clearDb():
    models.CheckInfo.objects.all().delete()

def sendMsg(msg):
    sk = socket.socket()
    sk.connect(("localhost", 8888))
    sk.sendall(bytes(msg, encoding="utf8"))
    accept_data = sk.recv(1024)  # conn.recv()接收客户端的内容，接收到的是bytes类型数据，
    recvmsg= str(accept_data, encoding="utf8")  # str(data,encoding="utf8")用“utf8”进行解码
    sk.close()
    return recvmsg