from idaapi import *
import idc
import audit_lib

def audit_memcpy(addr):
	code = audit_lib.GetApiParam(addr , 3)
	###record the param####
	###if eax trace till mov eax,xxxx or call xxxxx
	###else trace till mov xxx,src
	###if it is offset xxxx just skip
	if(idc.GetOpType(code,0)==o_imm):
		print "optype ",audit_lib.OpTypeName(idc.GetOpType(code,0))
		print "opvaule ", hex(idc.GetOperandValue(code,0))
		print "from immdiate just skip it!"
	else:
		print "Warning, Maybe Corrupted!"	