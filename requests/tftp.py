from sulley import *

s_initialize("RRQ")
s_static("\x00\x01")
s_string("filename")
s_delim("\x00",fuzzable=False)
s_group("mode",values=["netascii","octet","mail"])
if s_block_start("options",group="mode"):
	s_delim("\x00",fuzzable=False)
	
s_block_end()

s_initialize("WRQ")
s_static("\x00\x02")
s_string("filename")
s_delim("\x00",fuzzable=False)
s_group("mode",values=["netascii","octet","mail"])
if s_block_start("options",group="mode"):
	s_delim("\x00",fuzzable=False)
	
s_block_end()

s_initialize("DATA")
s_static("\x00\x03")
s_word("\x00\x01")
s_raw("\xaa\xcc")

s_initialize("ACK")
s_static("\x00\x04")
s_word("\x00\x01")
