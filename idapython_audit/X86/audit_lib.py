from idaapi import *
import idc
import idautils

def OpTypeName(op):
	if(op == o_void):
		return "o_void"
	elif(op == o_reg):
		return "o_reg"
	elif(op == o_mem):
		return "o_mem"
	elif(op == o_phrase):
		return "o_phrase"
	elif(op == o_displ):
		return "o_displ"
	elif(op == o_imm):
		return "o_imm"
	elif(op == o_far):
		return "o_far"
	elif(op == o_near):
		return "o_near"


'''now just resolve the push convention 
maybe someday will use the compiler signature to
automate the calling convention
back to find the push then return the addr'''

def GetApiParam(caller, n):
	code = caller
	count = 0
	while(True):
		if(count == n):
			break

		code = idc.FindCode(code, SEARCH_UP|SEARCH_NEXT)
			
		##	print "mnemonic is "+GetMnem(code)
		##	print "disass is "+GetDisasm(code)
		##	print "operand is "+GetOpnd(code,0)
	
		if("push" in idc.GetMnem(code)):
			count = count+1

			if(count ==n):
				return code



def AuditApiCall(funcname, auditfunc):
	
	print funcname
	
	func = idc.LocByName(funcname)

	print funcname + " func addr "
	print hex(func)

	if(func != BADADDR):
		for xref in idautils.XrefsTo(func,0):
			print xref.type,idautils.XrefTypeName(xref.type)
			print 'from',hex(xref.frm)
			print 'to',hex(xref.to)

			####audit func#####
			####not from an const####

			func_start = idc.GetFunctionAttr(xref.frm, idc.FUNCATTR_START)
			func_end = idc.GetFunctionAttr(xref.frm, idc.FUNCATTR_END)
			local_size = idc.GetFunctionAttr(xref.frm, idc.FUNCATTR_FRSIZE)

			auditfunc(xref.frm)	