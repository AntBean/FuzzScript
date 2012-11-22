from idaapi import *
import idc
import audit_lib

def audit_strcpy(addr):
	code = audit_lib.GetApiParam(addr, 2)
	if(idc.GetOpType(code,0)==o_imm):
		print "optype ",audit_lib.OpTypeName(idc.GetOpType(code,0))
		print "opvaule ", hex(idc.GetOperandValue(code,0))
						
		print "just skip it, source from const string!"

	else:
		print "Warning, Maybe Corrupted!"