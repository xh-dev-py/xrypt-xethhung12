```shell
pri={pri}
pub={pub}
openssl genrsa -out $pri 4096
openssl rsa -in $pri -outform PEM -pubout -out $pub
```