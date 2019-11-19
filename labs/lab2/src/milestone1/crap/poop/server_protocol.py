from .protocol_base import *

class PoopServerProtocol(PoopProtocolBase):
    def __init__(self):
        super().__init__()

    def data_received(self, data):
        print('POOP:--------------- server received new things ---------------')
        self.deserializer.update(data)
        if not self.connected:
            #print("Receiving packets in handshake")
            self.process_packet_unconnected()
        else:
            #print("receiving data packets")
            self.process_packet_connected()

    def process_packet_unconnected(self):
        for packet in self.deserializer.nextPackets():
            if packet.DEFINITION_IDENTIFIER == "poop.handshakepacket":
                if packet.status == HandshakePacket.ERROR:
                    continue  # TODO may need to resend error packet
                elif packet.status == HandshakePacket.NOT_STARTED:
                    #print('-- first step')
                    self.first_step(packet)
                elif packet.status == HandshakePacket.SUCCESS:
                    #print('-- second step')
                    self.second_step(packet)
            else:
                #print("-- server is not yet connected, but other types of packet received")
                p = HandshakePacket(status=HandshakePacket.ERROR, hash=0)
                phash = binascii.crc32(p.__serialize__()) & 0xffffffff
                p.hash = phash
                self.transport.write(p.__serialize__())
                

    def first_step(self, packet):
        synpacket = HandshakePacket(SYN=packet.SYN, status=packet.status, hash=0)
        synhash = binascii.crc32(synpacket.__serialize__()) & 0xffffffff
        if packet.SYN != FIELD_NOT_SET and synhash == packet.hash:
            status = HandshakePacket.SUCCESS
            # print("-- server received handshake packet with SYN=", packet.SYN,'ACK=',packet.ACK)
            self.ack = packet.SYN
            self.seq = self.syn
            p = HandshakePacket(SYN=self.syn, ACK=(self.ack + 1) % 2**32,  status=status, hash=0)
            ackhash = binascii.crc32(p.__serialize__()) & 0xffffffff
            p.hash = ackhash
            self.transport.write(p.__serialize__())
            # print('-- server sent first handshake packet with SYN=', self.syn, 'ACK=', (self.ack + 1) % 2**32)
        else:
            #print("-- Unset syn!!")
            p = HandshakePacket(
                status=HandshakePacket.ERROR, hash=0)

            ackhash = binascii.crc32(p.__serialize__()) & 0xffffffff
            p.hash = ackhash
            self.transport.write(p.__serialize__())

    def second_step(self, packet):
        if packet.ACK == (self.syn+1) % 2**32:
            #print("-- server received second handshake packet with SYN=",packet.SYN, 'ACK=', packet.ACK)
            self.connected = True
            print('POOP: server finish handshake');
            higherTransport = PoopTransport(self.transport, self)
            
            #print("SYN is: ", self.syn, " ACK is: ", self.ack)
            self.higherProtocol().connection_made(higherTransport)
            print('POOP: -- server set up higher protocol connection_made, connected')
        else:
            #print('-- error in ack number or status')
            #send error packets back
            status = HandshakePacket.ERROR
            p = HandshakePacket(status=status, hash=0)
            phash = binascii.crc32(p.__serialize__()) & 0xffffffff
            p.hash = phash
            self.transport.write(p.__serialize__())
        #print(self.syn, self.ack, "this is the upadted self syn and ack")

    def connection_made(self, transport):
        print("POOP: ------server connection made")
        self.transport = transport


PoopServerFactory = StackingProtocolFactory.CreateFactoryType(
    PoopServerProtocol
)
