from Crypto.Cipher import AES
import xml.dom.minidom as xml

class pyfv2:
	def __init__(self, encryptedRootPList):
		# read in encryptedRootPList
		self.encryptedRootPList = open(encryptedRootPList, 'rb').read()
		self.vaildRootPList = False

	def decrypt_encryptedRootPList(self, key):
		# Will decrypt EncryptedRoot.plist.wipekey file when provided
		# with key found at offset 176 in the core storage volume. Key
		# must be 16 bytes and must be binary, not the hex digest of
		# the key.

		# create pycrpto objects to decrypt encryptedRootPList
		enc = AES.new(key, AES.MODE_ECB)

		# xts tweak key for encryptedRootPList is all zeros
		encxts = AES.new('\x00' * 16, AES.MODE_ECB)

		# decrypt the plist
		ek2n = encxts.encrypt(self.inttoLE(0))
		# loop across entire encryptedRootPList
		plain = ''
		for i in range(0, len(self.encryptedRootPList), 16):
			plain += self.xor( enc.decrypt( self.xor(ek2n, self.encryptedRootPList[i:i+16]) ) , ek2n)
			ek2n = self._exponentiate_tweak(ek2n)

		# trim decrypted plist to expected size by file size
		self.decryptedRootPList = plain[:len(self.encryptedRootPList)]

		# test to see if the decrypted plist appears to be correct, While
		# not 100% accurate this test is a good approximation
		if self.decryptedRootPList[:5] == '<?xml':
			self.vaildRootPList = True

			# trim excess blocks from decryptedRootPList added by AES
			endOfPlist = self.decryptedRootPList.find('</plist>') + 8
			self.decryptedRootPList = self.decryptedRootPList[:endOfPlist]

			#parse XML plist
			self.parsedRootPList = xml.parseString(self.decryptedRootPList)

	# Internal function to decrypt a sector
	# from pytruecrypt thanks to Gareth Owen (github.com/owenson)
	def _decrypt_sector(self, enc, encxts, sector, ciphertext, offset=0):
		# Encrypt IV to produce XTS tweak
		ek2n = encxts.encrypt(self.inttoLE(sector))

		plain = '\x00' * offset #pad for offset
		for i in range(offset, 512, 16):
			# Decrypt and apply tweak according to XTS scheme
			plain += self.xor( self.enc.decrypt( self.xor(ek2n, ciphertext[i:i+16]) ) , ek2n)
			ek2n = self._exponentiate_tweak(ek2n)
		return plain

	# exponentiate tweak for next block (multiply by two in finite field)
	# from pytruecrypt thanks to Gareth Owen (github.com/owenson)
	def _exponentiate_tweak(self, ek2n):
		ek2n_i = self.LEtoint(ek2n)		       # Little Endian to python int
		ek2n_i = (ek2n_i << 1)			   # multiply by two using left shift
		if ek2n_i & (1<<128):			   # correct for carry
			ek2n_i ^= 0x87
		return self.inttoLE(ek2n_i)

	# hexdump print function
	# from pytruecrypt thanks to Gareth Owen (github.com/owenson)
	def hexdump(self, src, length=16):
	    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
	    lines = []
	    for c in xrange(0, len(src), length):
	        chars = src[c:c+length]
	        hex = ' '.join(["%02x" % ord(x) for x in chars])
	        printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
	        lines.append("%04x  %-*s  %s\n" % (c, length*3, hex, printable))
	    return ''.join(lines)

	# Little endian (int array) to integer
	def LEtoint(self, x):
		y = 0
		for i in range(16):
			y = y + (ord(x[i]) << i*8)
		return y

	# Integer to little endian (int array)
	# Note: must output 128bit block (ignoring higher significant bytes)
	# otherwise breaks xts code
	# from pytruecrypt thanks to Gareth Owen (github.com/owenson)
	def inttoLE(self, x):
		str=''
		for i in range(16):
			str += (chr((x & (0xFF << i*8)) >> i*8))
		return str

	# XOR two strings
	# from pytruecrypt thanks to Gareth Owen (github.com/owenson)
	def xor(self, a,b):
		return ''.join([chr(ord(a[i])^ord(b[i])) for i in range(len(a))])
