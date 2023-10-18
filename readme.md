# Installation

# Usage
```shell
from xcrypt_xethhung12.xcrypt import load_pub, load_pri, hybrid_encrypt, hybrid_decrypt
from Crypto.Cipher import PKCS1_OAEP as Cipher
from Crypto.Signature import PKCS1_v1_5

sender_pub = load_pub("rsa_public_key.pem")
sender_pri = load_pri("rsa_private_key.pem")

receiver_pub = load_pub("rsa_public_key_2.pem")
receiver_pri = load_pri("rsa_private_key_2.pem")

# normal case
key_str,iv_str,encrypt_data,sign = hybrid_encrypt(Cipher.new(receiver_pub), PKCS1_v1_5.new(sender_pri), "abcd1234567890".encode("utf-8"))
decrypted_data = hybrid_decrypt(Cipher.new(receiver_pri), PKCS1_v1_5.new(sender_pub), key_str, iv_str, encrypt_data, sign)
# decrypted_data -> b'abcd1234567890'

# incase the verify key fail
# there will be a exception raised
```

# Scripts

## Generate rsa key pair
```shell
pri={pri}
pub={pub}
openssl genrsa -out $pri 4096
openssl rsa -in $pri -outform PEM -pubout -out $pub
```