from Crypto.Cipher import AES
from util import *

class pyfv2:
	def __init__(self, encryptedRootPList):
		#read in encryptedRootPList
		self.encryptedRootPList = open(encryptedRootPList, 'rb').read()
		self.vaild = False

	def decrypt_encryptedRootPList(self, key):
		#create pycrpto objects to decrypt encryptedRootPList
		enc = AES.new(key, AES.MODE_ECB)
		if len(key) == 16:
			#xts tweak key for encryptedRootPList is all zeros
			encxts = AES.new('\x00' * 16, AES.MODE_ECB)
			self.decryptedRootPList = self._decrypt_sector(enc, encxts, 0, self.encryptedRootPList)
			if self.decryptedRootPList[:5] == '<?xml': self.vaild = True


	# Internal function to decrypt a sector
	def _decrypt_sector(self, enc, encxts, sector, ciphertext, offset=0):
		# Encrypt IV to produce XTS tweak
		ek2n = encxts.encrypt(inttoLE(sector))

		plain = '\x00' * offset #pad for offset
		for i in range(offset, 512, 16):
			# Decrypt and apply tweak according to XTS scheme
			plain += xor( enc.decrypt( xor(ek2n, ciphertext[i:i+16]) ) , ek2n)
			ek2n = self._exponentiate_tweak(ek2n)
		return plain

	# exponentiate tweak for next block (multiply by two in finite field)
	def _exponentiate_tweak(self, ek2n):
		ek2n_i = LEtoint(ek2n)		       # Little Endian to python int
		ek2n_i = (ek2n_i << 1)			   # multiply by two using left shift
		if ek2n_i & (1<<128):			   # correct for carry
			ek2n_i ^= 0x87
		return inttoLE(ek2n_i)
