from sulley import *
from requests import ftp

def recv_banner(sock):
	sock.recv(1024)

sess = sessions.session("ftp_test.session")
target = sessions.target("7.7.7.101",21)

sess.add_target(target)
sess.pre_send(recv_banner)
sess.connect(s_get("user"))
sess.connect(s_get("user"),s_get("pass"))
sess.connect(s_get("pass"),s_get("cwd"))
sess.connect(s_get("pass"),s_get("mkd"))
sess.connect(s_get("pass"),s_get("rmd"))
sess.connect(s_get("pass"),s_get("list"))
sess.connect(s_get("pass"),s_get("delete"))
sess.connect(s_get("pass"),s_get("port"))

sess.fuzz()