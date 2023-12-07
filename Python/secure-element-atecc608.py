from ctypes import Union
import time
import timeit
from cryptoauthlib import *
from cryptoauthlib.device import *
import jwt
import hmac
import hashlib
from cryptoauthlib.atjwt import *
from common import *
import re
import os
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
#from cryptography.utils import int_from_bytes, int_to_bytes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

"""
This class encapsulates operations on the Microchip ATECC608 secure element,
    including key management, HMAC generation, and signature verification using the lib https://github.com/MicrochipTech/cryptoauthlib/tree/main/python

"""
class ConfigsTests:

    #hexadecimal string representing the ASN.1 encoding of an object identifier (OID) for elliptic curve cryptography (ECC) with a 256-bit key length.
    SEQUENCE_OID_OCTECT_ECC_256 = "3059301306072A8648CE3D020106082A8648CE3D03010703420004".lower()
    cfg = ""

    def __init__(self):
        """
        Initializes the class and sets up the ATECC608 device.

        Raises:
            ValueError: If there is no slot configuration for the device.
            ValueError: If the device is unsupported.
        """
        read_write_config = {
            'ATECC608': {'clear': 8, 'encrypted': 5}
        }

        self.ATCA_SUCCESS = 0x00

        load_cryptoauthlib()

        self.cfg = cfg_ateccx08a_i2c_default()
        # need to check the address and bus of the device, can change depending on the board
        self.cfg.cfg.atcai2c.slave_address = 0x6a
        self.cfg.cfg.atcai2c.bus = 0

        assert self.ATCA_SUCCESS == atcab_init(self.cfg)

        # Check device type
        info = bytearray(4)
        assert atcab_info(info) == self.ATCA_SUCCESS
        dev_name = get_device_name(info)
        dev_type = get_device_type_id(dev_name)

        slots = read_write_config.get(dev_name)
        if slots is None:
            raise ValueError('No slot configuration for {}'.format(dev_name))

        # Read the config to find some setup values
        config_data = bytearray(128)
        assert self.ATCA_SUCCESS == atcab_read_config_zone(config_data)
        if dev_name == 'ATECC608':
            config = Atecc608Config.from_buffer(config_data)
        else:
            raise ValueError('Unsupported device {}'.format(dev_name))

        self.write_data = bytearray(72)
        self.read_data = bytearray(72)
        self.random1 = bytearray(32)
        self.random2 = bytearray(32)

    # def __init__(self, semlib):
    #     pass

    def write_pubkey_slot(self, slot, pubkey):
        """
        Writes a public key to the specified slot.

        Args:
            slot (int): The slot number to write the public key to.
            pubkey (bytes): The public key to write.

        Returns:
            None
        """
        assert atcab_write_pubkey(slot, pubkey) == self.ATCA_SUCCESS
        return
    
    def read_pubkey_slot(self, slot):
        """
        Reads the public key from the specified slot.

        Args:
            slot (int): The slot number from which to read the public key.

        Returns:
            bytearray: The public key read from the specified slot.
        """
        pubkey_read = bytearray(72)
        assert atcab_read_pubkey(slot, pubkey_read) == self.ATCA_SUCCESS

        return pubkey_read

    def get_pubkey_from_private_key(self, slot):
        """
        Retrieves the public key associated with the specified private key slot.

        Args:
            slot (int): The slot number of the private key.

        Returns:
            bytearray: The public key as a bytearray.

        """
        pubkey = bytearray(72)
        atcab_get_pubkey(slot, pubkey)
        return pubkey
    
    def convert_pubkey_to_pem(self, pubkey_data: bytes):
        """
        Converts the given public key data to PEM format.

        Args:
            pubkey_data (bytes): The public key data to be converted.

        Returns:
            str: The public key data in PEM format.
        """
        # sequência (30 + 59 + 3013) + oid + octect string 
        public_key_pem = bytearray.fromhex('3059301306072A8648CE3D020106082A8648CE3D03010703420004') + pubkey_data
        public_key_pem = '-----BEGIN PUBLIC KEY-----\n' + base64.b64encode(public_key_pem).decode('ascii') + '\n-----END PUBLIC KEY-----'
        #Convert the key into the cryptography format
        #public_key = serialization.load_pem_public_key(public_key_pem.encode('ascii'), default_backend())
        return public_key_pem

    def convert_pem_to_pubkey(self, pubkey_data: str):
        """
        Converts a PEM-encoded public key to its corresponding bytes representation.

        Args:
            pubkey_data (str): The PEM-encoded public key.

        Returns:
            bytes: The bytes representation of the public key.
        """

        try:
            cleaned_key = re.sub(r"-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----", "", pubkey_data, flags=re.DOTALL).strip()
        except Exception as e:
            print(e)

        hex_text = (base64.b64decode(cleaned_key).hex())
        key_bytes_hex = hex_text.replace(self.SEQUENCE_OID_OCTECT_ECC_256,"")

        return bytes.fromhex(key_bytes_hex)
    
    def convert_pem_to_pubkey_cryptography_lib(self, pub_key_pem: str):
        """
        Converts a PEM-encoded public key to a byte representation using the cryptography library.

        Args:
            pub_key_pem (str): The PEM-encoded public key.

        Returns:
            bytes: The byte representation of the public key.
        """

        public_key = serialization.load_pem_public_key(pub_key_pem.encode("utf-8"))        
        public_numbers = public_key.public_numbers()
        x_coordinate = public_numbers.x
        y_coordinate = public_numbers.y

        hex_x = format(x_coordinate, '064x')
        hex_y = format(y_coordinate, '064x')

        hex_representation = hex_x + hex_y

        return bytes.fromhex(hex_representation)
    
    def write_slot_bytes(self, data: bytes, slot: int):
        """
        Writes the specified data to the given slot in the ATECC608 chip.

        Args:
            data (bytes): The data to be written.
            slot (int): The slot number to write the data to.

        Returns:
            None
        """
        self.write_data = data

        assert atcab_write_bytes_zone(2, slot, 0, data, len(data)) == self.ATCA_SUCCESS
        print('    Write Success')

    def read_slot_bytes(self, slot:int, size: int):
        """
        Reads a specified number of bytes from a given slot in the ATECC608 chip.

        Args:
            slot (int): The slot number to read from.
            size (int): The number of bytes to read.

        Returns:
            bytes: The data read from the specified slot.
        """

        assert atcab_read_bytes_zone(2, slot, 0, self.read_data, size) == self.ATCA_SUCCESS

        return self.read_data


    def sign_device(self, digest, slot):
        """
        Sign message using an ATECC608

        Parameters:
        - digest: The message digest to be signed.
        - slot: The slot number of the ATECC device to use for signing.

        Returns:
        - signature: The signed message as a bytearray.
        """
        signature = bytearray(64)
        assert atcab_sign(slot, digest, signature) == self.ATCA_SUCCESS

        return signature

    def verify_device(self, message, signature, public_key):
        """
        Verify a signature using a device

        Parameters:
        message (bytes): The message to be verified
        signature (bytes): The signature to be verified
        public_key (bytes): The public key used for verification

        Returns:
        bool: True if the signature is valid, False otherwise
        """
        is_verified = AtcaReference(False)
        assert atcab_verify_extern(message, signature, public_key, is_verified) == self.ATCA_SUCCESS

        return bool(is_verified.value)

    def get_cfg(self):
        """
        Returns the configuration of the object.

        Returns:
            dict: The configuration of the object.
        """
        return self.cfg
    
    def verificaJWT(self, tokenJWT: str, pubkey: bytes, alg: str) -> dict:
        """ Método para verificação de tokens JWT

        Args:
            tokenJWT (str): Token JWT a ser verificado
            pubkey (bytes): Chave pública par da chave privada que gerou a assinatura do token JWT
            alg (str): Algoritmo de assinatura digital

        Returns:
            dict: Payload do token JWT
        """
        chave = None
        if isinstance(pubkey, bytes):
            chave = pubkey
        if isinstance(pubkey, str):
            chave = pubkey.encode("utf-8")
        try:
            payload = jwt.decode(tokenJWT, chave,
                                 algorithms=alg, verify=True)
            return payload
        except jwt.exceptions.InvalidSignatureError:
            return False
        except jwt.exceptions.InvalidAlgorithmError:
            return False
        
    def compute_hmac_sha256(self, key, message):
        """
        Computes the HMAC-SHA256 hash of the given message using the provided key according RFC 2104.

        Args:
            key (bytes): The key used for HMAC-SHA256.
            message (bytes): The message to compute the HMAC-SHA256 hash for.

        Returns:
            bytes: The HMAC-SHA256 hash of the message.

        Raises:
            None
        """
        # cont = 4
        # data_size = len(cont.to_bytes(4,'big'))
        # key_slot = 12
        # digest = bytearray(32)
        # target = 2
        # assert atcab_sha_hmac(cont.to_bytes(4,'big'), data_size, key_slot, digest, target) == Status.ATCA_SUCCESS

        if len(key) > 64:
            key = hashlib.sha256(key).digest()
        if len(key) < 64:
            key += b'\x00' * (64 - len(key))
        
        # Passos descritos na RFC para calcular o hmac https://datatracker.ietf.org/doc/html/rfc2104

        inner_hash = bytearray(32)
        outer_hash = bytearray(32)
        
        ipad = bytes(x ^ 0x36 for x in key)
        opad = bytes(x ^ 0x5C for x in key)

        inner_hash = hashlib.sha256(ipad + message).digest() 
        outer_hash= hashlib.sha256(opad + inner_hash).digest()    
        #atcab_hw_sha2_256((ipad + message),len(ipad + message), inner_hash)              
        #atcab_hw_sha2_256((opad + inner_hash),len(opad + inner_hash), outer_hash) 

        return outer_hash

if __name__ == "__main__":
    teste = ConfigsTests()
    #teste_sem_lib = ConfigsTests("")
    chs = bytearray(32)
    sha_digest = bytearray(32)
    size = len(chs)
    slot = 12
    slot1 = 11

    chs = os.urandom(32)
    cont = 4
    data_size = len(cont.to_bytes(4,'big'))
    key_slot = 12
    digest = bytearray(32)
    target = 2

    def sha_hw():
        atcab_hw_sha2_256(cont.to_bytes(4,'big'),data_size, sha_digest)
        return sha_digest

    #0.04200000
    execution_time_hardware = timeit.timeit(sha_hw, number=10)

    def sha_sw():
        digest = hashlib.sha256(cont.to_bytes(4,'big')).digest()
        return digest

    execution_time_software = timeit.timeit(sha_sw, number=10)

    print(f"Tempo em software SHA256: {execution_time_software}")
    print(f"Tempo em hardware SHA256: {execution_time_hardware}")


    def teste_hmac_software():
        hmac_software1 = hmac.new(chs, cont.to_bytes(4,'big'), hashlib.sha256).digest()
        return hmac_software1
    
    def teste_hmac_hardware():
        hmac = teste.compute_hmac_sha256(chs, cont.to_bytes(4, 'big'))
        return hmac

    execution_time_software = timeit.timeit(teste_hmac_software, number=10)

    print(f"Time software HMAC-SHA256: {execution_time_software}")

    execution_time_hardware = timeit.timeit(teste_hmac_hardware, number=10)

    print(f"Time hardware HMAC-SHA256: {execution_time_hardware}")

    print()
    
    print(f"\nTime with hmac gerado pelo software:\n{teste_hmac_software()}\n")

    print(f"\nTime with hmac gerado pelo hardware:\n{teste_hmac_hardware()}\n")

    # token = atjwt.PyJWT(slot, teste.cfg)
    # encoded = token.encode(claims, b'', algorithm='HS256')
    # print(f"Token com hmac gerado pelo device:\n{encoded}\n")

    # #decoded = token.decode(encoded, bytes(chs), algorithms=['HS256'])
    # #print("Token com hmac validado pelo device: ")
    # #print(decoded)

    # #tokenJWT_software = jwt.encode(
    # #                    claims, bytes(chs), algorithm="HS256")
    
    # #print(f"\nToken com hmac gerado pelo software:\n{tokenJWT_software}\n")

    # try:
    #     payload = jwt.decode(encoded, bytes(chs), algorithms="HS256")
    #     print(payload)
    # except jwt.exceptions.InvalidSignatureError:
    #     print(False)
    # except jwt.exceptions.InvalidAlgorithmError:
    #     print(False)
