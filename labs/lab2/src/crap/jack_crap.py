from playground.network.common import StackingProtocolFactory, StackingProtocol, StackingTransport
from playground.network.packet.fieldtypes import UINT8, STRING, BUFFER, UINT16, BOOL, UINT32
from playground.network.packet import PacketType
from playground.network.packet import FIELD_NOT_SET

from .poop.client_protocol import PoopClientProtocol
from .poop.server_protocol import PoopServerProtocol

from .packets_crap import *

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import datetime
import random, binascii, asyncio, os, hashlib



class CrapTransport(StackingTransport):        #highlever transport object
	def __init__(self, transport, crap_protocol):
		super().__init__(transport)
		print("CRAP: CrapTransport init here")
		self.crap_protocol = crap_protocol

	def write(self, data):
		print('CRAP: high level tried to write sth')
		en_data=self.crap_protocol.encryption_method.encrypt(self.crap_protocol.iv_self, data, None)
		self.crap_protocol.iv_self=(int.from_bytes(self.crap_protocol.iv_self, byteorder='big') + 1).to_bytes(12,'big')
		wrapdata=DataPacket(data=en_data)
		self.lowerTransport().write(wrapdata.__serialize__())

class CrapProtocolFather(StackingProtocol):
	def __init__(self):
		self.deserializer = CrapPacketType.Deserializer()
		self.connected=False		
		self.transport=None
		self.ecdh_private_key=None
		self.ecdh_public_key=None
		self.shared_key=None
		self.sign_key=None   # a private one\
		self.sign_key_public=None
		self.nonce=None
		self.cert=None
		self.cert_root=None
		self.cert_team=None
		self.cert_team_list=[]   #each is serializered cert_team
		self.cert_filepath='/home/jding/.playground/connectors/crap/'
		self.signature=None
		self.received_cert=None
		self.received_certchain=[]
		self.address_connect_agent=None
		self.iv_self=None
		self.iv_received=None
		self.encryption_method=None
		self.decryption_method=None
		self.hash123=[]
		self.start_generate()

	def start_generate(self):
		#generate ECDH keys
		self.ecdh_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
		self.ecdh_public_key= self.ecdh_private_key.public_key()
		#load the sign keys
		with open(self.cert_filepath+'signing_server.key', "rb") as fi:
			self.sign_key = serialization.load_pem_private_key(fi.read(), password=None, backend=default_backend())
		self.sign_key_public = self.sign_key.public_key()
		#generate nonce
		self.nonce=random.randint(0,2**8-1)
		#load the cert
		with open(self.cert_filepath+'20194_root.cert', 'rb') as f:
			self.cert_root=x509.load_pem_x509_certificate(f.read(), default_backend())
		with open(self.cert_filepath+'20194.3_signed.cert', 'rb') as f:
			self.cert_team=x509.load_pem_x509_certificate(f.read(), default_backend())
			self.cert_team_list.append(self.cert_team.public_bytes(serialization.Encoding.PEM))
		with open(self.cert_filepath+'signing_server.cert', 'rb') as f:
			self.cert=x509.load_pem_x509_certificate(f.read(), default_backend())					
		#generate signature for self.ecdh_public_key using self.sign_key
		message=self.ecdh_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
		self.signature = self.sign_key.sign(
			message,
			padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
			hashes.SHA256()
			)
		print('CRAP: finish start_generate')

	def shared_key_calu(self, inpublickey_bytes):
		print('CRAP: calu the shared key')
		inpublickey=serialization.load_pem_public_key(inpublickey_bytes, default_backend())
		self.shared_key = self.ecdh_private_key.exchange(ec.ECDH(), inpublickey)

	def verify_signature(self, publickey, signature, message):
		try:
			publickey.verify(
				signature,
				message,     #bytes
				padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.MAX_LENGTH),
				hashes.SHA256()
			)			
		except InvalidSignature:
			return False
		return True

	def verify_certificate(self):
		#print(self.received_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, self.address_connect_agent)
		if self.received_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value!=self.address_connect_agent:
			print('CRAP: error, received certificate playground address is not as the same as the incoming connection address')
			return False
		for recv_certchain in self.received_certchain:
			#print(recv_certchain.not_valid_before, recv_certchain.not_valid_after)
			if not (datetime.datetime.now()>=recv_certchain.not_valid_before and datetime.datetime.now()<=recv_certchain.not_valid_after):
				print('CRAP: error, received certificate chain elements timestamp expired')
				return False			
		#print(self.received_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, self.received_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)
		last_subject=self.received_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
		last_issuer=self.received_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
		flag_chain=0;
		for i in range(1, len(self.received_certchain)):
			#print(last_subject, last_issuer)			
			if self.received_certchain[i].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value!=last_issuer:
				flag_chain=1
			if self.received_certchain[i].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value not in last_subject:
				flag_chain=1
			if flag_chain==1:
				print('CRAP: error, received certificate chain subject and issuee not fit in the order or wrong')
				return False
			last_subject=self.received_certchain[i].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
			last_issuer=self.received_certchain[i].issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value			
		#print(last_subject, last_issuer)	
		return True

	def hash123_calu(self):
		m=hashlib.sha256()
		m.update(self.shared_key)
		h=m.digest()
		self.hash123.append(h)
		m=hashlib.sha256()
		m.update(h)
		h=m.digest()
		self.hash123.append(h)
		m=hashlib.sha256()
		m.update(h)
		h=m.digest()
		self.hash123.append(h)		

	def incoming_datapacket(self, recvpack):
		#print('CRAP: incoming_datapacket')
		if recvpack.DEFINITION_IDENTIFIER == "crap.datapacket":
			print('CRAP: received crap.datapacket')
			de_data=self.decryption_method.decrypt(self.iv_received, recvpack.data, None)
			self.iv_received=(int.from_bytes(self.iv_received, byteorder='big') + 1).to_bytes(12,'big')
			if de_data!=None:
				self.higherProtocol().data_received(de_data)
		else:
			print('CRAP: wrong input packet dropped, expected a crap.datapacket')
			self.dropconnection()

	def data_received(self, data):
		pass

	def dropconnection(self):		#send ERROR handshake packet and drop connection
		self.transport.write(HandshakePacket(status=HandshakePacket.ERROR).__serialize__())
		print('CRAP: cannot proceeed, drop connection')
		self.transport.close()
		self.connection_lost('Drop connection')

	def higherprotocol_setup(self):		#grant upper layer to start the session
		highertransport = CrapTransport(self.transport, self)
		self.higherProtocol().connection_made(highertransport)
		self.connected=True;

	def connection_lost(self, exc):
		self.higherProtocol().connection_lost(exc)
		print('CRAP:--shut down')


class CrapClientProtocol(CrapProtocolFather):
	def __init__(self):
		super().__init__()

	def data_received(self, data):
		print('CRAP: client received sth')
		self.deserializer.update(data)
		for recvpack in self.deserializer.nextPackets():
			if self.connected:
				self.incoming_datapacket(recvpack)
			else:
				if recvpack.DEFINITION_IDENTIFIER == "crap.handshakepacket":
					if recvpack.status == HandshakePacket.SUCCESS:
						print('CRAP: client received first incoming handshake')
						if (recvpack.pk==FIELD_NOT_SET or recvpack.signature==FIELD_NOT_SET or recvpack.nonce==FIELD_NOT_SET or recvpack.cert==FIELD_NOT_SET or recvpack.nonceSignature==FIELD_NOT_SET or recvpack.certChain==FIELD_NOT_SET):
							print('CRAP: received correpted handshakepacket, drop')
							self.dropconnection()
							return						
						self.received_cert=x509.load_pem_x509_certificate(recvpack.cert, default_backend())
						#verify the signature of server ecdh_public_key						
						if not self.verify_signature(self.received_cert.public_key(), recvpack.signature, recvpack.pk):
							print('CRAP: client CANNOT verified the signature of the pubkB')
							self.dropconnection()
							return							
						print('CRAP: client verified the signature of the pubkB')
						#verif the nonce signature
						if not self.verify_signature(self.received_cert.public_key(), recvpack.nonceSignature, str(self.nonce).encode('ASCII')):
							print('CRAP: client CANNOT verified the signature of the nonce')
							self.dropconnection()
							return
						print('CRAP: client verified the signature of the nonce')
						
						#verif the certificate
						self.received_certchain.append(self.received_cert)						
						for recvcert in recvpack.certChain:
							self.received_certchain.append(x509.load_pem_x509_certificate(recvcert, default_backend()))
						self.received_certchain.append(self.cert_root)
						if not self.verify_certificate()==True:
							print('CRAP: Client CANNOT verified the received certificate')
							self.dropconnection()
							return
						print('CRAP: Client verified the received certificate')

						#calculate the shared key, hash and the iva ivb etc for the datapacket transmission
						self.shared_key_calu(recvpack.pk)
						self.hash123_calu()
						print(self.hash123)
						self.iv_self=self.hash123[0][:12]
						self.iv_received=self.hash123[0][12:24]

						self.encryption_method=AESGCM(self.hash123[1][:16])
						self.decryption_method=AESGCM(self.hash123[2][:16])
						
						noncesign = self.sign_key.sign(
							#bytes(recvpack.nonce),
							str(recvpack.nonce).encode(),
							padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
							hashes.SHA256()
							)		
						sendpacket=HandshakePacket(
							status=HandshakePacket.SUCCESS,
							nonceSignature=noncesign
							)						
						self.transport.write(sendpacket.__serialize__())
						self.higherprotocol_setup()
						print('CRAP: client sent the second handshakepacket and setup higherprotocol')
				else:
					self.dropconnection()
					return				

	def connection_made(self, transport):
		print('CRAP: client connection made')
		self.transport=transport
		self.address_connect_agent=transport.get_extra_info("peername")[0]
		self.address_connect_agent='20194.3.6.9'
		##########################################print(self.address_connect_agent)
		sendpacket=HandshakePacket(
			status=HandshakePacket.NOT_STARTED,
			pk=self.ecdh_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),
			signature=self.signature,
			nonce=self.nonce,
			cert=self.cert.public_bytes(serialization.Encoding.PEM),
			certChain=self.cert_team_list
			)
		self.transport.write(sendpacket.__serialize__())
		print('CRAP: client sent first HandshakePacket')


class CrapServerProtocol(CrapProtocolFather):
	def __init__(self):
		super().__init__()

	def connection_made(self, transport):
		print('CRAP: server connection made')	
		self.transport=transport
		self.address_connect_agent=transport.get_extra_info("peername")[0]
		self.address_connect_agent='20194.3.6.9'

	def data_received(self, data):
		print('CRAP: server received sth')
		self.deserializer.update(data)
		for recvpack in self.deserializer.nextPackets():
			#print(recvpack.DEFINITION_IDENTIFIER, self.connected)
			if self.connected:
				self.incoming_datapacket(recvpack)
			else:				
				if recvpack.DEFINITION_IDENTIFIER == "crap.handshakepacket":
					if recvpack.status == HandshakePacket.NOT_STARTED:
						print('CRAP: server received first incoming handshake')
						if (recvpack.pk==FIELD_NOT_SET or recvpack.signature==FIELD_NOT_SET or recvpack.nonce==FIELD_NOT_SET or recvpack.cert==FIELD_NOT_SET or recvpack.certChain==FIELD_NOT_SET):
							print('CRAP: received correpted handshakepacket, drop')
							self.dropconnection()
							return			
						self.received_cert=x509.load_pem_x509_certificate(recvpack.cert, default_backend())
						if not self.verify_signature(self.received_cert.public_key(), recvpack.signature, recvpack.pk)==True:
							print('CRAP: server CANNOT verified the signature of the pubkA')
							self.dropconnection()
							return
						print('CRAP: server verified the signature of the pubkA')
						#self.received_certchain forma a complete cert chain from root to self.received_cert
						#in the sequence [self.received_cert, recvpack.certChain, self.cert_root]
						self.received_certchain.append(self.received_cert)						
						for recvcert in recvpack.certChain:
							self.received_certchain.append(x509.load_pem_x509_certificate(recvcert, default_backend()))
						self.received_certchain.append(self.cert_root)
						if not self.verify_certificate()==True:
							print('CRAP: server CANNOT verified the received certificate')
							self.dropconnection()
							return
						print('CRAP: server verified the received certificate')

						self.shared_key_calu(recvpack.pk)

						#sign the receive nonce with self.sign_key	
						noncesign = self.sign_key.sign(
							#bytes(recvpack.nonce),
							str(recvpack.nonce).encode(),
							padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
							hashes.SHA256()
							)
						sendpacket=HandshakePacket(
							status=HandshakePacket.SUCCESS,
							pk=self.ecdh_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),
							signature=self.signature,
							nonce=self.nonce,
							nonceSignature= noncesign,
							cert=self.cert.public_bytes(serialization.Encoding.PEM),
							certChain=self.cert_team_list
							)
						self.transport.write(sendpacket.__serialize__())
						print('CRAP: server sent first recall handshakepacket')

					if recvpack.status == HandshakePacket.SUCCESS:
						print('CRAP: server received second incoming handshake')
						if recvpack.nonceSignature==FIELD_NOT_SET:
							print('CRAP: received correpted handshakepacket, drop')
							self.dropconnection()
							return
						#if 1:
						if self.verify_signature(self.received_cert.public_key(), recvpack.nonceSignature, str(self.nonce).encode()):											
							print('CRAP: server verified the signature of the nonce')
							#calculate the  hash and the iva ivb etc for the datapacket transmission
							self.hash123_calu()
							print(self.hash123)
							self.iv_received=self.hash123[0][:12]
							self.iv_self=self.hash123[0][12:24]
							self.encryption_method=AESGCM(self.hash123[2][:16])
							self.decryption_method=AESGCM(self.hash123[1][:16])	

							self.higherprotocol_setup()
							print('CRAP: server setup higherprotocol')							
						else:
							print('CRAP: server CANNOT verified the signature of the nonce')
							self.dropconnection()
							return	



CrapClientFactory = StackingProtocolFactory.CreateFactoryType(PoopClientProtocol, CrapClientProtocol)

CrapServerFactory = StackingProtocolFactory.CreateFactoryType(PoopServerProtocol, CrapServerProtocol)
