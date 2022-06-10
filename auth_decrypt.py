#!/usr/bin/env python3

from argparse import ArgumentParser
from gzip import decompress
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long
from Crypto.Util.number import long_to_bytes
import binascii
def get_args():
	parser = ArgumentParser()
	
	parser.add_argument(
		'-p',
		dest='pubkey',
		help='Cobalt Strike\'s authkey.pub (see .jar file resources)',
		default="authkey.pub"
	)

	parser.add_argument(
		'-a',
		dest='authfile',
		help='Cobalt Strike\'s .auth file',
		default="cobaltstrike.auth"
	)

	args = parser.parse_args()
	return args

def decrypt(pubkey, authfile):
	with open(pubkey, 'rb') as f:
		key = RSA.importKey(f.read())

	with open(authfile, 'rb') as f:
		ciphertext = bytes_to_long(f.read())

	plaintext = long_to_bytes(
		pow(ciphertext, key.e, key.n)
	)
	
	unpadded = unpad(plaintext)
	with open('./outhex.bin','wb') as f:
		f.write(unpadded)
	header = unpadded[:4]
	data_len = int.from_bytes(unpadded[5:6], byteorder="big")
	data_len = data_len & 0xffff
	gzip_lic = unpadded[6:6+data_len]
	return header, gzip_lic

def unpad(padded):
	unpadded = b'\x00'.join(padded.split(b'\x00')[1:])
	return unpadded

def decode_license(gzip_lic):
	exprtime = int.from_bytes(gzip_lic[:4], byteorder="big")
	if(exprtime==29999999):
		end = "永不过期"
	else:
		end = str(exprtime)
	watermarkid = str(int.from_bytes(gzip_lic[4:8],byteorder="big"))
	is45 = int.from_bytes(gzip_lic[8:9],byteorder="big")
	if(is45 < 45):
		print('版本小于4.5 key版本为:%s',is45)
	#b2
	temp_len = int.from_bytes(gzip_lic[9:10],byteorder="big")
	temp = gzip_lic[10:10+temp_len]
	seeking = 10+temp_len
	#b3
	temp_len = int.from_bytes(gzip_lic[seeking:seeking+1],byteorder="big")
	seeking = seeking + 1
	temp = gzip_lic[seeking:seeking+temp_len]
	seeking = seeking + temp_len
	#b4
	temp_len = int.from_bytes(gzip_lic[seeking:seeking+1],byteorder="big")
	seeking = seeking + 1
	temp = gzip_lic[seeking:seeking+temp_len]
	seeking = seeking + temp_len
	#b5
	temp_len = int.from_bytes(gzip_lic[seeking:seeking+1],byteorder="big")
	seeking = seeking + 1
	temp = gzip_lic[seeking:seeking+temp_len]
	seeking = seeking + temp_len
	#b6
	temp_len = int.from_bytes(gzip_lic[seeking:seeking+1],byteorder="big")
	seeking = seeking + 1
	temp = gzip_lic[seeking:seeking+temp_len]
	seeking = seeking + temp_len
	#b7
	temp_len = int.from_bytes(gzip_lic[seeking:seeking+1],byteorder="big")
	seeking = seeking + 1
	temp = gzip_lic[seeking:seeking+temp_len]
	seeking = seeking + temp_len
	key = binascii.b2a_hex(temp)
	#b8
	#watermarkhash
	temp_len = int.from_bytes(gzip_lic[seeking:seeking+4],byteorder="big")
	seeking = seeking + 4
	temp = gzip_lic[seeking:seeking+temp_len]
	watermarkhash = str(temp,encoding='Utf8')

	license = {
		'key'		: key,
		'end'		: end,
		'watermarkid'	: watermarkid,
		'watermarkhash' : watermarkhash
	}

	return license

def print_license(license):
	print ('=== Cobalt Strike auth file details ===')
	print('License key:\t{0}'.format(license['key']))
	print('End date:\t{0}'.format(license['end']))
	print('Watermark:\t{0}'.format(license['watermarkid']))
	print('watermarkhash:\t{0}'.format(license['watermarkhash']))

def main():
	args = get_args()
	header, gzip_lic = decrypt(args.pubkey, args.authfile)

	if header != b'\xca\xfe\xc0\xd3':
		print('Invalid header!')
		exit(1)

	license = decode_license(gzip_lic)
	print_license(license)

if __name__ == '__main__':
	main()
