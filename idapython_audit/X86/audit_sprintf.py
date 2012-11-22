from idaapi import *
import idc
import audit_lib

def audit_sprintf(addr):
	code = audit_lib.GetApiParam(addr, 2)
	if(idc.GetOpType(code,0)==o_imm):
		print "optype ",audit_lib.OpTypeName(idc.GetOpType(code,0))
		print "opvaule ", hex(idc.GetOperandValue(code,0))
						
		fmt_addr = idc.GetOperandValue(code, 0)
		###print "Skip this Code, From the Global Data"				
		###get the text here####
		fmt_str = idc.GetString(fmt_addr)
		print fmt_str
						
		if("%s" in fmt_str):
			print "Warning, Maybe Corrupted!"
		else:
			print "just skip it, normal!"

	else:
		print "Warning, Maybe Corrupted!"