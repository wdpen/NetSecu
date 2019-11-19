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
import datetime
import random, binascii, asyncio, os



class CrapTransport(StackingTransport):        #highlever transport object
	def __init__(self, transport, crap_protocol):
		super().__init__(transport)
		print("CRAP: CrapTransport init here")
		self.crap_protocol = crap_protocol

	def write(self, data):
		print('CRAP: high level tried to write sth')
		wrapdata=DataPacket(data=data, signature=b'not implemented yet')
		self.lowerTransport().write(wrapdata.__serialize__())


class CrapProtocolFather(StackingProtocol):
	def __init__(self):
		self.deserializer = CrapPacketType.Deserializer()
		self.connected=False		
		self.transport=None
		self.ecdh_private_key=None
		self.ecdh_public_key=None
		self.sign_key=None   # a private one
		self.nonce=None
		self.cert=None
		self.signature=None
		self.received_cert=None
		self.start_generate()

	def start_generate(self):
		#generate ECDH keys
		self.ecdh_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
		self.ecdh_public_key= self.ecdh_private_key.public_key()
		#genereate sign keys
		self.sign_key=rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
		#generate nonce
		self.nonce=random.randint(0,2**8-1)
		#generate cert
		subject = issuer = x509.Name([
			x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
			x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Maryland"),
			x509.NameAttribute(NameOID.LOCALITY_NAME, u"Baltimore"),
			x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Jack Solution"),
			x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
		])
		self.cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
			self.sign_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(
			datetime.datetime.utcnow()).not_valid_after(
			datetime.datetime.utcnow() + datetime.timedelta(days=10)).add_extension(
			x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),critical=False,).sign(
			self.sign_key, hashes.SHA256(), default_backend())
		#generate signature for self.ecdh_public_key
		message=self.ecdh_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
		self.signature = self.sign_key.sign(
			message,
			padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
			hashes.SHA256()
			)
		print('CRAP: finish start_generate')

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

	def incoming_datapacket(self, recvpack):
		#print('CRAP: incoming_datapacket')
		if recvpack.DEFINITION_IDENTIFIER == "crap.datapacket":
			print('CRAP: received crap.datapacket')
			self.higherProtocol().data_received(recvpack.data)
		else:
			print('CRAP: wrong input packet dropped, expected a crap.datapacket')

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
						if (recvpack.pk==FIELD_NOT_SET or recvpack.signature==FIELD_NOT_SET or recvpack.nonce==FIELD_NOT_SET or recvpack.cert==FIELD_NOT_SET or recvpack.nonceSignature==FIELD_NOT_SET):
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
						if not self.verify_signature(self.received_cert.public_key(), recvpack.nonceSignature, bytes(self.nonce)):
							print('CRAP: client CANNOT verified the signature of the nonce')
							self.dropconnection()
							return
						print('CRAP: client verified the signature of the nonce')

						noncesign = self.sign_key.sign(
							bytes(recvpack.nonce),
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

	def connection_made(self, transport):
		print('CRAP: client connection made')
		self.transport=transport
		sendpacket=HandshakePacket(
			status=HandshakePacket.NOT_STARTED,
			pk=self.ecdh_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),
			signature=self.signature,
			nonce=self.nonce,
			cert=self.cert.public_bytes(serialization.Encoding.PEM)
			)
		self.transport.write(sendpacket.__serialize__())
		print('CRAP: client sent first HandshakePacket')


class CrapServerProtocol(CrapProtocolFather):
	def __init__(self):
		super().__init__()

	def connection_made(self, transport):
		print('CRAP: server connection made')	
		self.transport=transport

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
						if (recvpack.pk==FIELD_NOT_SET or recvpack.signature==FIELD_NOT_SET or recvpack.nonce==FIELD_NOT_SET or recvpack.cert==FIELD_NOT_SET):
							print('CRAP: received correpted handshakepacket, drop')
							self.dropconnection()
							return
						self.received_cert=x509.load_pem_x509_certificate(recvpack.cert, default_backend())
						if self.verify_signature(self.received_cert.public_key(), recvpack.signature, recvpack.pk)==True:
							print('CRAP: server verified the signature of the pubkA')							
							#sign the receive nonce with self.sign_key							
							noncesign = self.sign_key.sign(
								bytes(recvpack.nonce),
								padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
								hashes.SHA256()
								)
							
							sendpacket=HandshakePacket(
								status=HandshakePacket.SUCCESS,
								pk=self.ecdh_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),
								signature=self.signature,
								nonce=self.nonce,
								nonceSignature= noncesign,
								cert=self.cert.public_bytes(serialization.Encoding.PEM)
								)
							self.transport.write(sendpacket.__serialize__())
							print('CRAP: server sent first recall handshakepacket')															
						else:
							print('CRAP: server CANNOT verified the signature of the pubkA')
							self.dropconnection()
							return
					if recvpack.status == HandshakePacket.SUCCESS:
						print('CRAP: server received second incoming handshake')
						if recvpack.nonceSignature==FIELD_NOT_SET:
							print('CRAP: received correpted handshakepacket, drop')
							self.dropconnection()
							return
						if self.verify_signature(self.received_cert.public_key(), recvpack.nonceSignature, bytes(self.nonce)):											
							print('CRAP: server verified the signature of the nonce')
							self.higherprotocol_setup()
							print('CRAP: server setup higherprotocol')							
						else:
							print('CRAP: server CANNOT verified the signature of the nonce')
							self.dropconnection()
							return	



CrapClientFactory = StackingProtocolFactory.CreateFactoryType(PoopClientProtocol, CrapClientProtocol)

CrapServerFactory = StackingProtocolFactory.CreateFactoryType(PoopServerProtocol, CrapServerProtocol)
