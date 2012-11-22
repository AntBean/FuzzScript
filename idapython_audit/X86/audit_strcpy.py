from idaapi import *

func = LocByName("_strcpy")

print "_strcpy func addr "
print func

if(func != BADADDR):
	for xref in XrefsTo(func,0):
		print xref.type,XrefTypeName(xref.type)
		print 'from',hex(xref.frm)
		print 'to',hex(xref.to)

		####audit _strcpy#####
		####not from an const####

		func_start = GetFunctionAttr(xref.frm, FUNCATTR_START)
		func_end = GetFunctionAttr(xref.frm, FUNCATTR_END)
		local_size = GetFunctionAttr(xref.frm, FUNCATTR_FRSIZE)

		code = xref.frm
		count = 0
		while(True):
			if(count == 2):
				break

			code = FindCode(code, SEARCH_UP|SEARCH_NEXT)
			
			print "mnemonic is "+GetMnem(code)
			print "disass is "+GetDisasm(code)
			print "operand is "+GetOpnd(code,0)

			if("push" in GetMnem(code)):
				count = count+1

				if(count ==2):
					###record the param####
					###if eax trace till mov eax,xxxx or call xxxxx
					###else trace till mov xxx,src
					###if it is offset xxxx just skip
					if("offset" in GetOpnd(code,0)):
						print "Skip this Code, From the Global Data"
					else:
						print "Warning, Maybe Corrupted!"
				