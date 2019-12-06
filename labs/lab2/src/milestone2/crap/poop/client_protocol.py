from .protocol_base import *

class PoopClientProtocol(PoopProtocolBase):
    HANDSHAKE_ATTEMPTS = 5 #3 
    def __init__(self):
        super().__init__()
        self.handshake_count = 0 # only use this for handshake
        self.done_syn = False

    def data_received(self, data):
        print("POOP: ------------- client received new things -----------------")

        self.deserializer.update(data)
        if not self.connected:
            self.process_packet_unconnected()
        # connection successful
        else:
            self.process_packet_connected(is_client=True)
            
    def process_packet_unconnected(self):
        #print("data received")
        for recvpack in self.deserializer.nextPackets():
            #print("identifier", recvpack.DEFINITION_IDENTIFIER)
            if recvpack.DEFINITION_IDENTIFIER == "poop.handshakepacket":
                # print(self.syn, self.ack, "-------this is syn and ack in client handshake-------")
                # print(recvpack.SYN, recvpack.ACK, "-------this is syn and ack in packet-------")
                # Upon receiving the SUCCESS packet, the client checks if new SYN is old SYN + 1.  If it is correct, the client sends back to
                # server a packet with status SUCCESS
                if recvpack.status == HandshakePacket.SUCCESS:
                    self.verify_ack(recvpack)
                # Else, the client sends back to server a packet with status set to ERROR.
                else:
                    # TODO: do we still need ERROR??
                    handshake_packet = HandshakePacket(status=HandshakePacket.ERROR,hash=0)
                    hs_hash = binascii.crc32(handshake_packet.__serialize__()) & 0xffffffff
                    handshake_packet.hash = hs_hash
                    # self.transport.write(handshake_packet.__serialize__())
                    #print("-- sync did not match")

                    self.resend_handshake()
                    
            # wrong packet type when not connected
            else:
                # TODO: do we still need ERROR??
                handshake_packet = HandshakePacket(status=HandshakePacket.ERROR, hash=0)
                #print("-- we haven't connected yet")
                ackhash = binascii.crc32(ackpacket.__serialize__()) & 0xffffffff
                handshake_packet.hash = ackhash
                #self.transport.write(handshake_packet.__serialize__())
                self.resend_handshake()

    def resend_handshake(self):
        if self.done_syn:
            return
        if self.handshake_count < self.HANDSHAKE_ATTEMPTS and not self.done_syn:
            # resend packet
            handshake_packet = HandshakePacket(
                SYN=self.syn, status=HandshakePacket.NOT_STARTED, hash=0)
            hs_hash = binascii.crc32(handshake_packet.__serialize__()) & 0xffffffff
            handshake_packet.hash = hs_hash
            self.transport.write(handshake_packet.__serialize__())
            self.handshake_count += 1
            #print('-- client handshake_count', self.handshake_count)
            loop = asyncio.get_event_loop()
            loop.call_later(1, self.resend_handshake)
        else:
            print("Maximum attemps reached")
            # self.connection_lost("Maximum attempts reached")

    def verify_ack(self, epacket):
        ackpacket = HandshakePacket(SYN=epacket.SYN, ACK=epacket.ACK, status=epacket.status, hash=0)
        ackhash = binascii.crc32(ackpacket.__serialize__()) & 0xffffffff
        if epacket.ACK == (self.syn+1) % (2**32) and ackhash == epacket.hash:
            self.done_syn = True
            #print("-- client received handshake packet with SYN=",epacket.SYN, 'ACK=', epacket.ACK)
            self.ack = epacket.SYN
            handshake_packet = HandshakePacket(
                SYN=(self.syn + 1) % 2**32, ACK=(self.ack+1) % (2**32), status=HandshakePacket.SUCCESS, hash=0)

            ackhash = binascii.crc32(handshake_packet.__serialize__()) & 0xffffffff
            handshake_packet.hash = ackhash
            self.transport.write(handshake_packet.__serialize__())
            #print("-- client sent handshake packet with SYN=",self.syn + 1, 'ACK=', (self.ack+1) % (2**32))
            # call success connection
            self.success_connection()
        else:
            print("-- ACK not matching")
            # TODO: should I send an error message
            # self.transport.write(HandshakePacket(status=HandshakePacket.ERROR, error="SYN not matching").__serialize__())

            self.resend_handshake()

    def connection_made(self, transport):
        if self.done_syn:
            return
        print("POOP: -------- Connection made")
        self.transport = transport
        # create a new packet and send it to the other side
        handshake_packet = HandshakePacket(
            SYN=self.syn, status=HandshakePacket.NOT_STARTED, hash=0)
        hshash = binascii.crc32(handshake_packet.__serialize__()) & 0xffffffff
        handshake_packet.hash = hshash
        self.transport.write(handshake_packet.__serialize__())
        print('-- client sent first handshake packet with SYN=', self.syn)
        self.handshake_count += 1
        print('-- client handshake_count', self.handshake_count)
        loop = asyncio.get_event_loop()
        loop.call_later(1, self.connection_made, self.transport)

    def success_connection(self):
        self.seq = self.syn
        self.connected = True
        self.done_syn = True
        # pass transport upwards
        higher_transport = PoopTransport(self.transport, self)
        #print("SYN is: ", self.syn, " ACK is: ", self.ack)
        self.higherProtocol().connection_made(higher_transport)
        print('POOP:-- client set up higher protocol connection_made, connected')
        print('POOP:-- client reset handshake count')
        self.handshake_count = 0


PoopClientFactory = StackingProtocolFactory.CreateFactoryType(
    PoopClientProtocol
)
