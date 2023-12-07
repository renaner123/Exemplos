from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
import base64

# Script para demonstrar como gerar o fingerprint sobre um certificado digital usando sha-256 e a representação em base64URL

# O exemplo gera um certificado digital x.509 a partir de um par de chaves também gerado

class ChaveCripto():

    def __init__(self, chave: str):
        """ Encapsula uma chave criptográfica
        Args:
            chave (str): chave criptográfica na forma de string
        """
        self.chave_str = chave
        self.chave_bytes = chave.encode('utf-8')

class CriptoDAF:
    ''' 
        Classe para operações criptográficas do DAF Virtual
    '''

    def __init__(self):
        pass

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
    
    def gera_certificado(privkey: ChaveCripto, pubkey: ChaveCripto, organizationName: str, organizationUnitName: str,
                                countryName: str, stateName: str, localityName: str, commonName: str) -> bytes:
                from cryptography.hazmat.backends import default_backend
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
        

if __name__ == "__main__":
    
    # cria um par de chaves para gerar um certificado
    private_key_new, public_Key_new = CriptoDAF.gera_chave_EC_p384()
    # cria o certificado x.509 no formato PEM
    #certificado = CriptoDAF.gera_certificado(
    #    private_key_new, public_Key_new, 'SEF', 'GESAC', 'BR', 'Santa Catarina', 'Florianopolis', 'sef.sc.gov.br')

    with open("sef-cert-new.pem", "r") as arquivo:
        certificado = (arquivo.read())
    
    # encapsula o certificado PEM para extrair o fingerprint
    certificado_x509 = x509.load_pem_x509_certificate(certificado.encode('utf-8'))
    # calcula o fingerprint usando sha-256
    fingerprint_bytes = certificado_x509.fingerprint(hashes.SHA256())  
    # representa o fingerprint bytes em base64URL retirando o padding
    fingerprint_base64URL_bytes = base64.urlsafe_b64encode(fingerprint_bytes).replace(b"=", b"").decode('utf-8') 
    # representa o fingerprint Hexa em base64URL retirando o padding
    fingerprint_base64URL_hex = base64.urlsafe_b64encode(fingerprint_bytes.hex().encode('utf-8')).replace(b"=", b"").decode('utf-8') 


    print('--------------------------------------------------------------------------------------')
    print("Calculo do fingerprint usando sha-256")
    print('--------------------------------------------------------------------------------------')
    print(f'fingerprint em bytes       (tamanho: {len(str(fingerprint_bytes))}) : {fingerprint_bytes}')
    print(f'bytes para base64URL       (tamanho: {len(fingerprint_base64URL_bytes)}) : {fingerprint_base64URL_bytes}')
    print('---------------------------------------------------------------------------------------')
    print(f'fingerprint em hexa        (tamanho: {len(str(fingerprint_bytes.hex))}) : {fingerprint_bytes.hex()}')
    print(f'Hexa para base64URL        (tamanho: {len(fingerprint_base64URL_hex)}) : {fingerprint_base64URL_hex}')


