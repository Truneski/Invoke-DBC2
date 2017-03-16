from Crypto.Cipher import AES
from pkcs7 import PKCS7Encoder
import pkcs7,threading, base64

text='''
runCLI
1
whoami
MCxfQigRsDQevlBS
'''
key = 'secret#456!23key'
iv = 'Key@123Key@123fd'
aes = AES.new(key, AES.MODE_CBC, iv)
encoder = PKCS7Encoder()
pad_text = encoder.encode(text)
cipher = aes.encrypt(pad_text)
enc_cipher = base64.b64encode(cipher)
print enc_cipher


