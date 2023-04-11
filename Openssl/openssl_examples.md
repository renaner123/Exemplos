1 - Gerar número aleatório
* openssl rand -base64 8

2 - Gerar hash (SHA;MD5) de um arquivo.
* openssl dgst -sha1 arquivo.txt
* openssl dgst -md5 arquivo.txt

3 - Verificar arquivo gerado no passo anterior.

4 - Critografar arquivo com AES/DES.
* *openssl enc -aes256 -e -in arquivo.txt -out arquivo.enc.txt
* *openssl enc -des -e -in arquivo.txt -out arquivo.enc.txt

5 - Descritografar arquivo com AES/DES.
* openssl enc -aes256 -d -in arquivo.enc.txt -out arquivo.txt
* openssl enc -des -d -in arquivo.enc.txt -out arquivo.txt

6 - Gera chave privada RSA.
* openssl genrsa -out chave.key 1024
* openssl genrsa -aes256 -out chave.key 1024

7 - Criar chave pública RSA.
* openssl rsa -in chave.key -pubout -out chave.pub

8 - Criptografar arquivo com algoritmo assimétrico RSA
 * openssl rsautl -in teste.txt -out teste.rsa -encrypt -pubin -inkey pubkey.pem

9 - Descriptografar arquivo com algoritmo assimétrico RSA
* openssl rsautl -in teste.rsa -out teste.rec -decrypt -inkey key.pem

10 -Assinar hash com chave privada.
* openssl dgst -sha256 -sign chave.key -out hash.sha256 arquivo

11 -Verificar assinatura com chave pública.
* openssl dgst -sha256 -verify chave.pub -signature hash.sha256 arquivo

12-Retirar chave pública do certificado.
* openssl x509 -in snakeoil.crt -pubkey -noout > snakeoil.pub

13 -Gerar uma chave privada e requisição de assinatura de certificado (CSR)
* openssl req -out CSR.csr -new -newkey rsa:2048 -nodes -keyout privateKey.key

14 - Gerar um certificado auto-assinado
* openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout privateKey.key -out certificate.crt

15 - Gerar uma requisição de assinatura de certificado (CSR) para uma chave privada existente
* openssl req -out CSR.csr -key privateKey.key -new




http://www.sslshopper.com/article-most-common-openssl-commands.html

Comandos Gerais
---------------------
1 - Gerar uma chave privada e requisição de assinatura de certificado (CSR)
*  openssl req -out CSR.csr -new -newkey rsa:2048 -nodes -keyout privateKey.key

2 - Gerar um certificado auto-assinado
* openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout privateKey.key -out certificate.crt

3 - Gerar uma requisição de assinatura de certificado (CSR) para uma chave privada existente
* openssl req -out CSR.csr -key privateKey.key -new

4 - Gerar uma requisição de assinatura de certificado baseado em um certificado existente
* openssl x509 -x509toreq -in certificate.crt -out CSR.csr -signkey privateKey.key

5- Remover senha da chave privada
* openssl rsa -in privateKey.pem -out newPrivate.pem

Comandos para checagem usando openSSL
----------------------------------------------------
1 - Checar a requisição de assinatura de certificado.
* openssl req -text -noout -verify -in CSR.csr

2 - Checar a chave privada.
* openssl rsa -in privateKey.key -check

3 - Checar o certificado.
* openssl x509 -in certificate.crt -text -noout

4 - Checar arquivo pkcs* *12 (.pfx ou .p12)
* openssl pkcs12 -info -in keyStore.p12

Debugar utilizando OpenSSL
-----------------------------------
1 - Verifique o hash MD5 da chave pública se é igual ao do CSR ou da chave privada
* openssl x509 -noout -modulus -in certificate.crt | openssl md5
* openssl rsa -noout -modulus -in privateKey.key | openssl md5
* openssl req -noout -modulus -in CSR.csr | openssl md5

2 - Verifique a conexão SSL . Todos os certificados (incluindo os intermediários) devem ser exibidos
* openssl s_client -connect www.paypal.com:443

Conversões de formatos utilizando OpenSSL
-----------------------------------------------------

1 - Converter arquivo DER (.crt .cer .der) para PEM
* openssl x509 -inform der -in certificate.cer -out certificate.pem

2- Converter de  PEM para DER
* openssl x509 -outform der -in certificate.pem -out certificate.der

3 - Converter de arquivo PKCS* *12 (.pfx .p12) contendo chave privada e certificados para PEM
* openssl pkcs12 -in keyStore.pfx -out keyStore.pem -nodes

You can add -nocerts to only output the private key or add -nokeys to only output the certificates.

4 - Converter um certificado PEM com chave privada para PKCS* *12 (.pfx .p12)
*  openssl pkcs12 -export -out certificate.pfx -inkey privateKey.key -in certificate.crt -certfile CACert.crt

------------------------------------------------------


5 - Assinar uma requisição
* openssl x509 -req -days 365 -in csr.pem -signkey privatekey.pem -out public.crt

6 - Gerar chave Ec
* openssl ecparam -name secp384r1 -genkey -out privateKey.pem
* openssl ec -in privateKey.pem -pubout -out publicKey.pem

4 - Converter uma chave para pkcs8
* openssl pkcs8 -topk8 -nocrypt -in private-sef.pem -out p8file.pem


