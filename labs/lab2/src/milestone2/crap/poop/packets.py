from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT8, STRING, BUFFER, UINT16, BOOL, UINT32 
from playground.network.packet.fieldtypes.attributes import Optional

class PoopPacketType(PacketType):
    DEFINITION_IDENTIFIER = "poop"
    DEFINITION_VERSION = "1.0"

class DataPacket(PoopPacketType):
    DEFINITION_IDENTIFIER = "poop.datapacket"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("seq", UINT32({Optional: True})),
        ("hash", UINT32),
        ("data", BUFFER({Optional: True})),
        ("ACK", UINT32({Optional: True}))
    ]

'''
class AckPacket(PoopPacketType):
    DEFINITION_IDENTIFIER = "poop.ackpacket"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("ack", UINT32),
        (ackhash", UINT32)
    ]

class ShutdownPacket(PoopPacketType):
    DEFINITION_IDENTIFIER = "poop.shutdownpacket"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
        ("FIN", UINT32({Optional: True})),
        ("FACK", UINT32({Optional: True}))
    ]
'''
class HandshakePacket(PoopPacketType):
    DEFINITION_IDENTIFIER = "poop.handshakepacket"
    DEFINITION_VERSION = "1.0"
    NOT_STARTED = 0
    SUCCESS     = 1
    ERROR       = 2
    
    FIELDS = [      
        ("SYN", UINT32({Optional:True})),
        ("ACK", UINT32({Optional:True})),
        ("status", UINT8),
        ("hash", UINT32)
    ]

class ShutdownPacket(PoopPacketType):
    DEFINITION_IDENTIFIER = "poop.shutdownpacket"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
        ("FIN", UINT32),
        ("hash", UINT32)
    ]
