# GET Command Generator
from pysnmp.entity import engine, config
from pysnmp.carrier.asynsock.dgram import udp
from pysnmp.entity.rfc3413 import cmdgen

snmpEngine = engine.SnmpEngine()

# v1/2 setup
config.addV1System(snmpEngine, 'test-agent', 'public')

# v3 setup
config.addV3User(
    snmpEngine, 'test-user',
    config.usmHMACMD5AuthProtocol, 'authkey1',
    config.usmDESPrivProtocol, 'privkey1'
#    config.usmAesCfb128Protocol, 'privkey1'
    )

# Transport params
config.addTargetParams(snmpEngine, 'myParams', 'test-user', 'authPriv')
#config.addTargetParams(snmpEngine, 'myParams', 'test-agent', 'noAuthNoPriv', 1)

# Transport addresses
config.addTargetAddr(
    snmpEngine, 'myRouter', config.snmpUDPDomain,
    ('127.0.0.1', 161), 'myParams'
    )

# Setup transport endpoint
config.addSocketTransport(
    snmpEngine,
    udp.domainName,
    udp.UdpSocketTransport().openClientMode()
    )

def cbFun(sendRequestHandle, errorIndication, errorStatus, errorIndex,
          varBinds, cbCtx):
    cbCtx['errorIndication'] = errorIndication
    cbCtx['errorStatus'] = errorStatus
    cbCtx['errorIndex'] = errorIndex
    cbCtx['varBinds'] = varBinds

# Used to pass data from callback function
cbCtx = {}
    
cmdgen.GetCommandGenerator().sendReq(
    snmpEngine, 'myRouter', (((1,3,6,1,2,1,1,1,0), None),), cbFun, cbCtx
    )

snmpEngine.transportDispatcher.runDispatcher()
if cbCtx['errorIndication']:
    print cbCtx['errorIndication']
elif cbCtx['errorStatus']:
    print cbCtx['errorStatus'].prettyPrint()
else:
    for oid, val in cbCtx['varBinds']:
        print '%s = %s' % (oid.prettyPrint(), val.prettyPrint())