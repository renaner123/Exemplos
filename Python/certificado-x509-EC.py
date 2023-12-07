from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from typing import Tuple
import random
import hmac
import hashlib


# Le um par de chaves EC 384 dos arquivos(chaves atuais) .pem, gera um novo par de chaves EC 384 
# e gera um novo certificado usando a chave privada atual com a nova chave pública.

class ChaveCripto():

    def __init__(self, chave: str):
            """ 
            Inicializa a classe ChaveCriptografica com uma chave criptográfica.

            Args:
                chave (str): A chave criptográfica na forma de string.
            """
            self.chave_str = chave
            self.chave_bytes = chave.encode('utf-8')

class Certificado():

    def __init__(self, cert: str):
        """ Encapsula um certificado

        Args:
            cert (str): certificado na forma de string
        """
        certificado_x509 = x509.load_pem_x509_certificate(cert.encode('utf-8'))

        self.assinatura = certificado_x509.signature

        self.chave_publica = ChaveCripto(certificado_x509.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8'))
        self.key_public = certificado_x509.public_key()
        self.certificado_str = cert
        self.certificado_bytes = certificado_x509.public_bytes(
            serialization.Encoding.PEM)
        self.conteudo_assinado = certificado_x509.tbs_certificate_bytes
        self.signature_algorithm_oid = certificado_x509.signature_algorithm_oid
        self.signature_hash_algorithm = certificado_x509.signature_hash_algorithm
    

class CriptoDAF:
    ''' 
        Classe para operações criptográficas do DAF Virtual
    '''

    def __init__(self):
        pass

    def gera_chave_RSA(len: int) -> Tuple[ChaveCripto, ChaveCripto]:
        """ Método para geração de chaves RSA

        Args:
            len (int): Tamanho da chave

        Returns:
            Tuple[ChaveCripto,ChaveCripto]: Chave privada e chave pública 
        """
        key = RSA.generate(len)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        private_key = ChaveCripto(private_key.decode('utf-8'))
        public_key = ChaveCripto(public_key.decode('utf-8'))

        return private_key, public_key

    @staticmethod
    def gera_chave_EC_p384():
        """ Método para geração de chaves EC com curva 384

        Returns:
            Tuple[ChaveCripto,ChaveCripto]: Chave privada e chave pública 
        """

        private_key = ec.generate_private_key(ec.SECP384R1)
        public_key = private_key.public_key()
        private_key = private_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.NoEncryption())

        public_key = public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)

        private_key = ChaveCripto(private_key.decode('utf-8'))
        public_key = ChaveCripto(public_key.decode('utf-8'))
        return private_key, public_key

    @staticmethod
    def verifica_assinatura_EC_P384(msg:bytes, sig:bytes, pubkey:ChaveCripto) -> bool:
        """ Método para verificação de assinatura digital com chaves EC P-384

        Args:
            msg (bytes): Mensagem que foi assinada
            sig (bytes): Assinatura digital
            pubkey (bytes): Chave pública par da chave privada que gerou a assinatura (PEM)

        Returns:
            bool: Sucesso ou falha na verificação
        """

        try:
            pubkey = serialization.load_pem_public_key(pubkey.chave_bytes)
            pubkey.verify(sig, msg, ec.ECDSA(hashes.SHA384()))
            return True
        except:
            return False     

    def geraCertificado(privkey: ChaveCripto, pubkey: ChaveCripto, organizationName: str, organizationUnitName: str,
                        countryName: str, stateName: str, localityName: str, commonName: str) -> bytes:
        """
        Generates an X.509 certificate using the provided private key, public key, and certificate details.

        Args:
            privkey (ChaveCripto): The private key used to sign the certificate.
            pubkey (ChaveCripto): The public key associated with the certificate.
            organizationName (str): The name of the organization.
            organizationUnitName (str): The name of the organizational unit.
            countryName (str): The country name.
            stateName (str): The state or province name.
            localityName (str): The locality or city name.
            commonName (str): The common name for the certificate.

        Returns:
            bytes: The X.509 certificate encoded in PEM format.
        """
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives import serialization
        from cryptography.x509.oid import NameOID
        import datetime

        privkey = serialization.load_pem_private_key(
            privkey.chave_bytes, password=None)
        pubkey = serialization.load_pem_public_key(pubkey.chave_bytes)

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, organizationName),
                                                  x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,
                                                                    organizationUnitName), x509.NameAttribute(
                NameOID.COUNTRY_NAME, countryName), x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, stateName),
                                                  x509.NameAttribute(NameOID.LOCALITY_NAME, localityName),
                                                  x509.NameAttribute(NameOID.COMMON_NAME, commonName)]))

        builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, organizationName),
                                                 x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,
                                                                   organizationUnitName), x509.NameAttribute(
                NameOID.COUNTRY_NAME, countryName), x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, stateName),
                                                 x509.NameAttribute(NameOID.LOCALITY_NAME, localityName),
                                                 x509.NameAttribute(NameOID.COMMON_NAME, commonName)]))

        one_day = datetime.timedelta(1, 0, 0)
        builder = builder.not_valid_before(
            datetime.datetime.today() - one_day)
        builder = builder.not_valid_after(
            datetime.datetime.today() + (one_day * 365 * 10))

        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(pubkey)

        cert = builder.sign(
            private_key=privkey, algorithm=hashes.SHA384(), backend=default_backend())

        return cert.public_bytes(serialization.Encoding.PEM)
        
class salvarEmArquivos():
    """ 
    Classe responsável por salvar chaves e certificados em arquivos .pem.
    """

    def __init__(self) -> None:
        pass

    def salvarChavesEmArquivoPem(nomeArquivo: str, conteudo: str):
        """
        Salva o conteúdo das chaves em um arquivo .pem.

        Args:
            nomeArquivo (str): O nome do arquivo .pem a ser criado.
            conteudo (str): O conteúdo das chaves a serem salvos.

        Returns:
            None
        """
        with open(nomeArquivo + ".pem", "w") as arquivo:
            arquivo.write(conteudo)

    def salvarCertificado(certificado: bytes):
        """
        Salva o certificado em um arquivo .pem.

        Args:
            certificado (bytes): O certificado a ser salvo.

        Returns:
            None
        """
        with open('sef-cert-new.pem', 'w') as file:
            file.write(certificado.decode('utf-8'))


# Le um par de chaves EC 384 dos arquivos(chaves atuais) .pem, gera um novo par de chaves EC 384 
# e gera um novo certificado usando a chave privada atual com a nova chave pública.

if __name__ == "__main__":

    private_key_sef = ""
    public_Key_sef  = ""
    private_key_new= ""
    public_Key_new  = ""
    certificado_new = ""

    # private_key_sef, public_Key_sef = CriptoDAF.gera_chave_RSA(4096)

    # private_key_ateste, public_Key_ateste = CriptoDAF.gera_chave_RSA(4096)

    with open("sef-priv-ec.pem", "r") as arquivo:
        private_key_sef = ChaveCripto(arquivo.read())

    with open("sef-pub-ec.pem", "r") as arquivo:
        public_Key_sef = ChaveCripto(arquivo.read())

    # with open("sef-priv-new.pem", "r") as arquivo:
    #     private_key_new = ChaveCripto(arquivo.read())

    # with open("sef-pub-new.pem", "r") as arquivo:
    #     public_Key_new = ChaveCripto(arquivo.read())

    # with open("sef-cert-new.pem", "r") as arquivo:
    #     certificado_new = Certificado(arquivo.read())

    
    private_key_new, public_Key_new = CriptoDAF.gera_chave_EC_p384()
    
    certificado = CriptoDAF.geraCertificado(
        private_key_sef, public_Key_new, 'SEF', 'GESAC', 'BR', 'Santa Catarina', 'Florianopolis', 'sef.sc.gov.br')

    salvarEmArquivos.salvarChavesEmArquivoPem("sef-priv-new",private_key_new.chave_str)
    salvarEmArquivos.salvarChavesEmArquivoPem("sef-pub-new",public_Key_new.chave_str)  

    # salvarEmArquivos.salvarChavesEmArquivoPem("ateste-priv-RSA-4096",private_key_sef.chave_str)
    # salvarEmArquivos.salvarChavesEmArquivoPem("ateste-pub-RSA-4096",public_Key_sef.chave_str) 
    salvarEmArquivos.salvarCertificado(certificado)

    #print(CriptoDAF.verifica_assinatura_EC_P384(certificado_new.conteudo_assinado,certificado_new.assinatura,public_Key_sef))


    
