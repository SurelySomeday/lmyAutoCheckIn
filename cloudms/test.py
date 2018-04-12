def delUser(username):
    msg=dict();
    tmp = list()
    with open('users.txt', 'r+') as f:
        flag = True
        print("ok")
        for line in f:
            print("tt")
            linedata = line.split("--")
            print("%s  !=  %s".format(linedata[0],username))
            if linedata[0] != username:
                tmp.append(line)
            else:
                flag = False
        if flag==True:
            msg['delMsg'] = '用户不存在！'
        else:
            msg['delMsg'] = '删除成功！'

        for line in tmp:
            f.write(line)
    return msg


