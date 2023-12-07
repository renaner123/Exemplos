from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

class Chave():

    def __init__(self, chave: str):
        """ Encapsula uma chave criptográfica

        Args:
            chave (str): chave criptográfica na forma de string
        """
        self.chave_str = chave
        self.chave_bytes = chave.encode('utf-8')

class Assinador():

    def __init__(self) -> None:
        pass


    def gera_Assinatura_ECDSA256(data: bytes, privkey: Chave) -> bytes:
        """ Método para geração de assinatura digital com o esquema ECDSA SHA256

        Args:
            msg (bytes): Mensagem a ser assinada
            privkey (bytes): Chave privada (PEM)

        Returns:
            bytes: Assinatura digital
        """

        private_key = serialization.load_pem_private_key(privkey.chave_bytes, password=None)
        signature = private_key.sign(
            data,
            ec.ECDSA(hashes.SHA256())
        )

        return signature


if __name__ == "__main__" :

    privkey = ""

    with open("priv.pem") as file:
        privkey = Chave(file.read())

    # conteudo a ser assinado
    conteudo_hex = "020900aef1cd3580a5d7ab300a06082a8648ce3d040302306a310b3009060355040613024252310b300906035504080c0253433111300f06035504070c0853616f204a6f7365310e300c060355040a0c054c61534544310d300b060355040b0c0449465343311c301a06035504030c13312e6c617365642e696673632e6564752e62723020170d3232313231313232323832375a180f33303232303431333232323832375a306a310b3009060355040613024252310b300906035504080c0253433111300f06035504070c0853616f204a6f7365310e300c060355040a0c054c61534544310d300b060355040b0c0449465343311c301a06035504030c13312e6c617365642e696673632e6564752e627230819b301006072a8648ce3d020106052b810400230381860004000898347568ae0c703c860cda0d945a578e638e09953f8d13c99bb91dedad57e2f601434e84454294412cad8d1f19d25a5cd4239b1b4ce4e9c9c4d35edec33aaef60191942191c4bab386284b24a1350d19050b89ff16472ce16a35c0104c8f077873bb1d7adb0165878639e820156d25532e634db1c0672fe63d519f560f97bf3f372b"

    # representa os dados em binário
    data =conteudo_hex.encode("utf-8")

    # gera a assinatura ecdsa com sha256
    assinatura = Assinador.gera_Assinatura_ECDSA256(data,privkey)

    print("Assinatura em hexadecimal:")
    print(assinatura.hex())

    # Salva assinatura em arquivo, caso queira validar com openssl
    with open("assinatura.bin", "wb") as file:
         file.write(assinatura)
    # Salva conteudo em arquivo, caso queira validar com openssl
    with open("conteudo.bin", "wb") as file:
        file.write(data)     

    # Verificar assinatura
    # openssl dgst -sha256 -verify pub-pkcs.pem -signature assinatura.bin conteudo.bin
