from sulley import *

s_initialize("user")
s_static("USER")
s_delim(" ",fuzzable=False)
s_string("anonymous")
s_static("\r\n")

s_initialize("pass")
s_static("PASS")
s_delim(" ",fuzzable=False)
s_string("anonymous")
s_static("\r\n")

s_initialize("cwd")
s_static("CWD")
s_delim(" ",fuzzable=False)
s_string("Hello")
s_static("\r\n")

s_initialize("mkd")
s_static("MKD")
s_delim(" ",fuzzable=False)
s_string("Hello1")
s_static("\r\n")

s_initialize("rmd")
s_static("RMD")
s_delim(" ",fuzzable=False)
s_string("Hello1")
s_static("\r\n")

s_initialize("list")
s_static("LIST")
s_delim(" ",fuzzable=False)
s_string("Hello")
s_static("\r\n")

s_initialize("delete")
s_static("DELE")
s_delim(" ",fuzzable=False)
s_string("test.txt")
s_static("\r\n")


s_initialize("port")
s_static("PORT")
s_delim(" ",fuzzable=False)
s_string("7,7,7,101,10,1")
s_static("\r\n")
