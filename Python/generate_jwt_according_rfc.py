import json
import hmac
import base64
import hashlib

def base64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def create_jwt(key, payload):
    """
    Creates a JSON Web Token (JWT) using the specified key and payload according https://datatracker.ietf.org/doc/html/rfc2104

    Args:
        key (str): The secret key used for signing the JWT.
        payload (dict): The payload data to be included in the JWT.

    Returns:
        str: The generated JWT.

    """
    header = "{\"alg\": \"HS256\",\"typ\": \"JWT\"}"
    encoded_header = base64url_encode(json.dumps(header).encode('utf-8'))

    print("encoded_header:", encoded_header, "\n")
    encoded_payload = base64url_encode(json.dumps(payload).encode('utf-8'))

    print("encoded_payload:", encoded_payload, "\n")
    data = f"{encoded_header}.{encoded_payload}".encode('utf-8')
    print("data:", data, "\n")
    
    hmac_generate = hmac.new(bytes.fromhex(key), data, hashlib.sha256).digest()
    print("hmac:", hmac_generate.hex(), "\n")

    signature = base64url_encode(hmac_generate)
    
    return f"{data.decode('utf-8')}.{signature}"

if __name__ == "__main__":
    key = "dfdea2309b2004b41151b76ebf8eaae2dd9ba79deecd6ba4b6e29017412ca6266b068952055a363039da6ec5b9535e0fa4799757a94d3627885475c662acb27a"

    payload = "{\"sub\": \"renan\"}"
    
    jwt_token = create_jwt(key, payload)
    print("JWT:", jwt_token)

