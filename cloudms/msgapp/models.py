from django.db import models

# Create your models here.

#用户信息
class UserInfo(models.Model):
    username = models.CharField(max_length=20, primary_key=True)
    password = models.CharField(max_length=40)
    date = models.CharField(max_length=50)

#签到记录
class CheckInfo(models.Model):
    fullname = models.CharField(max_length=40)
    username = models.CharField(max_length=20)
    coursename = models.CharField(max_length=40)
    date = models.CharField(max_length=50)
