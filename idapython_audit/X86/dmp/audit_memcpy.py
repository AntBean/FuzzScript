from idaapi import *


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



func = LocByName("j__memcpy")

print "_memcpy func addr "
print hex(func)

if(func != BADADDR):
	for xref in XrefsTo(func,0):
		print xref.type,XrefTypeName(xref.type)
		print 'from',hex(xref.frm)
		print 'to',hex(xref.to)

		####audit _memcpy#####
		####not from an const####

		func_start = GetFunctionAttr(xref.frm, FUNCATTR_START)
		func_end = GetFunctionAttr(xref.frm, FUNCATTR_END)
		local_size = GetFunctionAttr(xref.frm, FUNCATTR_FRSIZE)

		code = xref.frm
		count = 0
		while(True):
			if(count == 3):
				break

			code = FindCode(code, SEARCH_UP|SEARCH_NEXT)
			
		##	print "mnemonic is "+GetMnem(code)
		##	print "disass is "+GetDisasm(code)
		##	print "operand is "+GetOpnd(code,0)

			if("push" in GetMnem(code)):
				count = count+1

				if(count ==3):
					###record the param####
					###if eax trace till mov eax,xxxx or call xxxxx
					###else trace till mov xxx,src
					###if it is offset xxxx just skip
					if(GetOpType(code,0)==o_imm):
						print "optype ",OpTypeName(GetOpType(code,0))
						print "opvaule ", hex(GetOperandValue(code,0))
						print "from immdiate just skip it!"
					else:
						print "Warning, Maybe Corrupted!"						
				
				