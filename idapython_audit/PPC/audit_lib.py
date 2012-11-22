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


'''
search back 
1 r3
2 r4
3 r5
4 r6
'''


def GetApiParam(caller, n):
    
    regstr={"r3", "r4", "r5", "r6"}

    reg = regstr[n-1]

    code = caller
    count = 0

    while(True):
        code = idc.FindCode(code, SEARCH_UP|SEARCH_NEXT)
            
        ##    print "mnemonic is "+GetMnem(code)
        ##    print "disass is "+GetDisasm(code)
        ##    print "operand is "+GetOpnd(code,0)
        if(reg == "r3"):
            ##blrl or bl
            if("bl" in GetDisasm(code)):
                return code            

        if(reg == idc.GetOpnd(code,0)):
            return code



###trace api call to find the first mtlr reg  btlr
def TraceApiCall(code):
    print "operand 0 is "+idc.GetOpnd(code,0)
    print "operand 1 is "+idc.GetOpnd(code,1)
    print "operand 2 is "+idc.GetOpnd(code,2)
    
    reg = idc.GetOpnd(code,0)
    
    ### search down to find caller  it cannt deal with such situation: 
    ###    addi r10, r10, VOS_sprintf@l
    ###    b addr
    ###     in the above code, the trace should follow addr to find the right call
    ###    
    
    func_end = idc.GetFunctionAttr(code, idc.FUNCATTR_END)
    
    instruct = "mtlr "+reg

    while(code < func_end):
        code = idc.FindCode(code, SEARCH_DOWN|SEARCH_NEXT)
        ### search "mtlr r10"
        if(("mtlr"==idc.GetMnem(code)) and (idc.GetOpnd(code,1) == reg)):
            print idc.GetOpnd(code,1)
            print "Get the instruct! "+ idc.GetDisasm(code)
            
            while(code < func_end):
                code = idc.FindCode(code, SEARCH_DOWN|SEARCH_NEXT)
                
                if("blrl" in idc.GetDisasm(code)):
                    print "api call " + idc.GetDisasm(code)+" from ",hex(code)
                    print "mnem "+idc.GetMnem(code)
                    return code


def AuditApiCall(funcname, auditfunc):
    
    print funcname
    
    func = idc.LocByName(funcname)

    print funcname + " func addr "
    print hex(func)

    count = 0

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
            ###Data offset  eg: lis r10, VOS_sprintf@h
            ###            addi r10, r10, VOS_sprintf@l
            if(xref.type == 1):
                print "disass is "+idc.GetDisasm(xref.frm)
                if("add" in idc.GetDisasm(xref.frm)):
                    caller = TraceApiCall(xref.frm)
                    auditfunc(caller)
                    break            
            else:
                caller= xref.frm
            ##    auditfunc(caller)    

            #### bl 17 Code_Near_Call

            #### li 1 Data_Offset

            #### addi
