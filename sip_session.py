from sulley import *
from requests import sip

sess = sessions.session("sip_test.session",proto="udp")
target = sessions.target("7.7.7.101",5060)

sess.add_target(target)

sess.connect(s_get("INVITE"))

sess.fuzz()