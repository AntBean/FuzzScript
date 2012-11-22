from idaapi import *
import audit_lib
import audit_strcpy
import audit_memcpy
import audit_sprintf

audit_map = {"j__strcpy":audit_strcpy.audit_strcpy , "j__memcpy":audit_memcpy.audit_memcpy, "__imp__sprintf":audit_sprintf.audit_sprintf}


for funcname in audit_map.keys():

	audit_lib.AuditApiCall(funcname, audit_map.get(funcname))