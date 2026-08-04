import hmac
import hashlib
from cryptography.fernet import Fernet  # type: ignore[import]
def encrypt_pan(card_number: str, key: bytes)->str:
    f= Fernet(key)
    encrypted_bytes = f.encrypt(card_number.encode())
    return encrypted_bytes.decode()

def decrypt_pan(ciphertext: str,key: bytes)->str:
    f= Fernet(key)
    decrypted_bytes = f.decrypt(ciphertext.encode())
    return decrypted_bytes.decode()

def normalise(card_number: str):
    cleaned = card_number.replace("-","").replace(" ","")
    return cleaned

def luhn_check(card_number: str) ->bool:
    reversed_number = card_number[::-1]
    total=0;
    
    for index,digit in enumerate(reversed_number):
        num = int(digit)
        if index%2==1:
            num*=2
            if num>9:
                num -=9
            total+=num
        else:
            total+=num

    return total%10==0

def mask_pan(card_number: str) -> str:
    lastfour = card_number[-4:]
    return f"**** **** **** {lastfour}"



def hash_pan(card_number : str, secret: bytes)->str:
    return hmac.new(secret,card_number.encode(), hashlib.sha256).hexdigest()



