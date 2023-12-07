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


class ChaveCripto():
    """Classe que encapsula uma chave criptográfica."""

    def __init__(self, chave: str):
        """Inicializa a classe ChaveCripto.

        Args:
            chave (str): chave criptográfica na forma de string
        """
        self.chave_str = chave
        self.chave_bytes = chave.encode('utf-8')

class Certificado():
    """
    Classe que encapsula um certificado X509.

    Args:
        cert (str): O certificado na forma de string.
    """

    def __init__(self, cert: str):
        """Inicializa a classe Certificado.

        Args:
            cert (str): O certificado na forma de string.
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

    def gera_certificado(privkey: ChaveCripto, pubkey: ChaveCripto, organizationName: str, organizationUnitName: str,
                                countryName: str, stateName: str, localityName: str, commonName: str) -> bytes:
        """ Método para geração de certificado X.509

        Args:
            privkey (ChaveCripto): Chave privada
            pubkey (ChaveCripto): Chave pública
            organizationName (str): Nome da organização
            organizationUnitName (str): Nome da unidade organizacional
            countryName (str): Nome do país
            stateName (str): Nome do estado ou província
            localityName (str): Nome da localidade
            commonName (str): Nome comum

        Returns:
            bytes: Certificado X.509 em formato PEM
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
            private_key=privkey, algorithm=hashes.SHA512(), backend=default_backend())

        return cert.public_bytes(serialization.Encoding.PEM)
        

class salvarEmArquivos():

    def __init__(self) -> None:
         pass

    def salvarChavesEmArquivoPem(nomeArquivo: str, conteudo: str):
         with open(nomeArquivo+".pem", "w") as arquivo:
            arquivo.write(conteudo)       

    def salvarCertificado(certificado : bytes):
        with open('sef-cert.pem', 'w') as file:
            file.write(certificado.decode('utf-8'))

if __name__ == "__main__":

    private_key_sef = ""
    public_Key_sef  = ""
    private_key_ateste = ""
    public_Key_ateste  = ""

    private_key_sef, public_Key_sef = CriptoDAF.gera_chave_RSA(4096)

    private_key_ateste, public_Key_ateste = CriptoDAF.gera_chave_RSA(4096)


    certificado = CriptoDAF.gera_certificado(
        private_key_sef, public_Key_sef, 'SEF', 'GESAC', 'BR', 'Santa Catarina', 'Florianopolis', 'sef.sc.gov.br')


    salvarEmArquivos.salvarChavesEmArquivoPem("sef-priv-RSA-4096",private_key_sef.chave_str)
    salvarEmArquivos.salvarChavesEmArquivoPem("sef-pub-RSA-4096",public_Key_sef.chave_str)  

    salvarEmArquivos.salvarChavesEmArquivoPem("ateste-priv-RSA-4096",private_key_sef.chave_str)
    salvarEmArquivos.salvarChavesEmArquivoPem("ateste-pub-RSA-4096",public_Key_sef.chave_str) 
    salvarEmArquivos.salvarCertificado(certificado)


    
