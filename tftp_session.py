from sulley import *
from requests import tftp

sess = sessions.session("tftp_test.session",proto="udp")
target = sessions.target("7.7.7.101",69)
###target.netmon = pedrpc.client("7.7.7.101",26001)
###target.netmon = pedrpc.client
sess.add_target(target)

sess.connect(s_get("RRQ"))
sess.connect(s_get("WRQ"))
sess.connect(s_get("RRQ"),s_get("ACK"))
sess.connect(s_get("WRQ"),s_get("DATA"))

sess.fuzz()
