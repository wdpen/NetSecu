from playground.network.common import StackingProtocolFactory, StackingProtocol, StackingTransport
import logging
from playground.network.packet import PacketType
from .packets import *
from playground.network.packet import FIELD_NOT_SET
from playground.network.packet.fieldtypes import UINT8, STRING, BUFFER, UINT16, BOOL, UINT32
import random
import binascii
import asyncio, time
from collections import deque

MAXIMUM_DATA_SIZE = 15000
#MAXIMUM_DATA_SIZE=100
time_out_INTERVAL = 5

class PoopTransport(StackingTransport):
    """
    definition for transport
    """

    def __init__(self, transport, poop_protocol):
        super().__init__(transport)
        print("Init poop protocol here")
        self.poop_protocol = poop_protocol
        self.count = 0  # only use this for shutdown

    def write(self, data):
        print('POOP: ** higher protocol tries to write a new data')
        # break down packet
        #print(data)
        #print("length of data is: ", len(data))
        for i in range(0,len(data), MAXIMUM_DATA_SIZE):
            datastream = data[i:i+MAXIMUM_DATA_SIZE]
            #print("data stream: ", datastream)
            #print("current data: ", self.poop_protocol.curr_datapack)
            if self.poop_protocol.curr_datapack is None:
                #if self.poop_protocol.curr_datapack.data==b'':
                datapack = DataPacket(
                    data=datastream, seq=self.poop_protocol.seq, hash=0)
                #print(datapack.data)
                datahash = binascii.crc32(
                    datapack.__serialize__()) & 0xffffffff
                datapack.hash = datahash
                self.lowerTransport().write(datapack.__serialize__())
                # record current packet sent, and wait for ACK
                self.poop_protocol.curr_datapack = datapack
                loop = asyncio.get_event_loop()
                loop.call_later(time_out_INTERVAL, self.poop_protocol.data_time_out, datapack)
            else:
                #print("write to 'data to write'")
                self.poop_protocol.data_to_write.append(datastream)

    def close(self):
        if self.poop_protocol.curr_datapack is not None:
            print("Give current datapacket another timeout")
            loop = asyncio.get_event_loop()
            loop.call_later(time_out_INTERVAL, self.close)
            return
        if self.poop_protocol.shutdownflag:
            print('already ack the shutdown successfully')
            return
        print("step 1 of Shutdown")
        self.poop_protocol.readyShutdownFlag = True
        if self.count == 3:
            print("I have resend FIN to you 3 fucking times. Shutting down now. Bye bye!")
            self.lowerTransport().close()
            return
        time.sleep(0.5) 
        # Only write when needed
        shutdownPacket = ShutdownPacket(FIN=self.poop_protocol.seq, hash=0)
        shutdownhash = binascii.crc32(shutdownPacket.__serialize__()) & 0xffffffff
        shutdownPacket.hash = shutdownhash
        self.lowerTransport().write(shutdownPacket.__serialize__()) 
        print("Fin is sent with value: ", shutdownPacket.FIN)
        self.count += 1
        loop = asyncio.get_event_loop()
        loop.call_later(time_out_INTERVAL, self.close)
        return

class PoopProtocolBase(StackingProtocol):
    """
    definition for protocol
    """

    def __init__(self):
        super().__init__()
        self.syn = random.randint(0, 2**32-1)
        self.ack = None
        self.transport = None
        self.connected = False
        self.deserializer = PoopPacketType.Deserializer()
        self.seq = None
        self.data_to_write = deque()
        self.curr_datapack = None  # no data waited to be ack, idle state
        self.shutdownflag = False # this is for timeout shutdown
        self.readyShutdownFlag = False # this is for waiting the ACK from other side.
        self.other_shutdown = False
        self.count = 1

    def process_packet_connected(self, is_client=False):
        for epacket in self.deserializer.nextPackets():
            if epacket.DEFINITION_IDENTIFIER == "poop.datapacket":
                #print("seq is: ", epacket.seq)
                #print("ack is: ", epacket.ACK)
                if not epacket.ACK == FIELD_NOT_SET and not epacket.data == FIELD_NOT_SET:
                    #print('--both field ACK and data were set?')
                    #TODO What do I need to do for this case?
                    continue
                if epacket.ACK == FIELD_NOT_SET:
                    #print('-- received a data poop.datapacket with seq =', epacket.seq)
                    self.process_data(epacket)
                elif epacket.data == FIELD_NOT_SET:
                    if self.readyShutdownFlag:
                        #print('--received ack packet for FIN shutdown packet')
                        self.process_shutdown_fin(epacket)
                    else:
                        #print('-- received a ack poop.datapacket with ack =', epacket.ACK)
                        self.process_ack(epacket)
            if epacket.DEFINITION_IDENTIFIER == "poop.shutdownpacket":
                #print('-- received a poop.shutdownpacket with seq =',epacket.FIN)
                self.process_shutdown(epacket)

            if epacket.DEFINITION_IDENTIFIER == "poop.handshakepacket" and is_client:
                #print('-- receive a poop.handshakepacket')
                #print('-- handshake status ', epacket.status, "handshake SYN ", epacket.SYN)
                if self.ack == epacket.SYN:
                    #print('-- resend handshake packet')
                    self.resend_handshake()
                    self.connected = False
                else:
                    print('-- probably someone trying to screw up with me')

    def resend_handshake(self):
        pass

    def process_shutdown_fin(self, epacket):
        # process shutdown after sending fin
        # we wait for the FACK to come back correctly
        test_packet = DataPacket(ACK=self.seq, hash=0)
        test_hash = binascii.crc32(test_packet.__serialize__()) & 0xffffffff
        if test_hash == epacket.hash and test_packet.ACK == self.seq:
            #print("ack message is correct. shutdown")
            self.shutdownflag = True
            self.transport.close()
            return
        else:
            # kick start resend. simply wait for timeout
            return 
         
    def process_shutdown(self, epacket):
        '''
        if self.count == 1:
            print("Dropping first packet")
            self.count = 0
            return # drop the first fin packet
        '''
        p = ShutdownPacket(FIN=self.ack,hash=0)
        phash = binascii.crc32(p.__serialize__()) & 0xffffffff
            
        ackpacket = DataPacket(ACK=epacket.FIN, hash=0)
        ackhash = binascii.crc32(ackpacket.__serialize__()) & 0xffffffff
        ackpacket.hash = ackhash
        self.transport.write(ackpacket.__serialize__())
        # Since window size is 1, once receive the FIN it should have received the rest
        if epacket.FIN == self.ack and epacket.hash == phash:
            # correct fin, ready to shutdown
            self.shutdownflag = True
            self.transport.close()
            return 
        else:
            # Resend a Ackpacket
            # This case should never happen in window size of 1
            #print("Not finished because the FIN is wrong")
            return 

    def process_data(self, epacket):
        # check hash
        test_packet = DataPacket(data=epacket.data, seq=epacket.seq, hash=0)
        test_hash = binascii.crc32(test_packet.__serialize__()) & 0xffffffff

        if (epacket.hash != test_hash):
            #print("failing because hash is incorrect")
            # we send what we previously acked
            datapack1 = DataPacket(ACK=self.ack-1, hash=0)
            ackhash = binascii.crc32(datapack1.__serialize__()) & 0xffffffff
            datapack1.hash = ackhash
            self.transport.write(datapack1.__serialize__())
            return
        elif (epacket.seq != (self.ack)%2**32):
            #print("failing because sequence is incorrect with ack, seq is: {}, ack is: {}".format(epacket.seq, self.ack))
            # we send what we previously acked
            datapack1 = DataPacket(ACK=self.ack-1, hash=0)
            if(epacket.seq < (self.ack)%2**32):
                print("newly added: already acked this packet for sure")
                datapack1 = DataPacket(ACK=epacket.seq, hash=0)
            ackhash = binascii.crc32(datapack1.__serialize__()) & 0xffffffff
            datapack1.hash = ackhash
            self.transport.write(datapack1.__serialize__())
            return
        elif (epacket.hash == test_hash) and (epacket.seq == (self.ack)%2**32):
            # ack the received data
            datapack1 = DataPacket(ACK=self.ack, hash=0)
            ackhash = binascii.crc32(datapack1.__serialize__()) & 0xffffffff
            datapack1.hash = ackhash
            self.transport.write(datapack1.__serialize__()) 

            # increment ack
            self.ack = (self.ack+1) % (2**32)
            # pass to higher protocol
            self.higherProtocol().data_received(epacket.data)            
            #print('-- sent a ack packet to confirm a receiving of data: ACK ', datapack1.ACK)
            return
        else:
            datapack1 = DataPacket(ACK=self.ack, hash=0)
            ackhash = binascii.crc32(datapack1.__serialize__()) & 0xffffffff
            datapack1.hash = ackhash
            self.transport.write(datapack1.__serialize__()) 
            #print('-- sent a ack packet to discard the data, ACK is: ', self.ack)
            return 
    def process_ack(self, epacket):
        # check hash
        test_packet = DataPacket(ACK=self.seq, hash=0)
        test_hash = binascii.crc32(test_packet.__serialize__()) & 0xffffffff
        if test_hash == epacket.hash:
            #print("ack message from server is correct")
            # increase seq
            self.seq = (self.seq+1) % (2**32)
            try:
                # get next data
                datastream = self.data_to_write.popleft()
                # update curr_datapack
                datapack = DataPacket(data=datastream, seq=self.seq, hash=0)
                datahash = binascii.crc32(
                    datapack.__serialize__()) & 0xffffffff
                datapack.hash = datahash
                # send data
                self.transport.write(datapack.__serialize__())
                # update current datapacket
                self.curr_datapack = datapack
                # timeout
                loop = asyncio.get_event_loop()
                loop.call_later(time_out_INTERVAL,
                                self.data_time_out, datapack)

            except IndexError:
                self.curr_datapack = None
                return
        else:
            #print("------ I cannot ack you correctly. Resend!!!")
            # resend
            if self.curr_datapack is not None:
                self.transport.write(self.curr_datapack.__serialize__())

    def data_time_out(self, datapack):
        # check if ack has been recieved
        if self.curr_datapack is not None:
            if self.curr_datapack.seq == datapack.seq:
                # resend
                #print("resend because of timeout, packet seq is: ", datapack.seq)
                self.transport.write(self.curr_datapack.__serialize__())
                loop = asyncio.get_event_loop()
                loop.call_later(time_out_INTERVAL,
                                self.data_time_out, datapack)

    def connection_lost(self, exc):
        self.higherProtocol().connection_lost(exc)
        print('POOP:--shut down')
        print(exc)
