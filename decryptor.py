import os
from Crypto.Cipher import AES
from base64 import b64decode

value="http://10.21.200.50/key=Z2igSNGo+qfqpeHho2EL+Q9bljHZc8GsnJZ9F0MOPPY=&iv=ouzDB5yS8sOQR8gBiQ+hIw==&pc=OIK-CLIENT"

IV = b64decode(b'ouzDB5yS8sOQR8gBiQ+hIw==')
KEY = b64decode(b'Z2igSNGo+qfqpeHho2EL+Q9bljHZc8GsnJZ9F0MOPPY=')
cipher = AES.new(KEY, AES.MODE_CBC, IV)

enc_files = os.listdir('Share')
for enc_file in enc_files:
    dec_file = '.'.join(enc_file.split('.')[:-1])
    
    with open(f'Share/{enc_file}', 'rb') as fin, \
         open(f'Share_dec/{dec_file}', 'wb') as fout:
        enc_data = fin.read()
        dec = cipher.decrypt(enc_data)[16:].strip(b'\x00')
        fout.write(dec)
