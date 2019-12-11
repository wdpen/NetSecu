from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT8, STRING, BUFFER, UINT16, BOOL, UINT32, LIST
from playground.network.packet.fieldtypes.attributes import Optional

class CrapPacketType(PacketType):
    DEFINITION_IDENTIFIER = "crap"
    DEFINITION_VERSION = "1.0"
    
class HandshakePacket(CrapPacketType):
    DEFINITION_IDENTIFIER = "crap.handshakepacket"
    DEFINITION_VERSION = "1.0"

    NOT_STARTED = 0
    SUCCESS     = 1
    ERROR       = 2
    
    FIELDS = [
        ("status", UINT8),
        ("nonce", UINT32({Optional:True})),
        ("nonceSignature", BUFFER({Optional:True})),
        ("signature", BUFFER({Optional:True})),
        ("pk", BUFFER({Optional:True})),
        ("cert", BUFFER({Optional:True})),
        ("certChain", LIST(BUFFER, {Optional:True}))
    ]

class DataPacket(CrapPacketType):
    DEFINITION_IDENTIFIER = "crap.datapacket"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("data", BUFFER)
        #("signature", BUFFER)
    ]
