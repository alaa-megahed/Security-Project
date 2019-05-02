#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Apr 28 13:56:16 2019

@author: mona
"""
import numpy as np
from LSBSteg import *
import json
import time
import random

import hashlib, os, base64
from Crypto.Cipher import AES


# these are final variable enumerating the types of messages
broadcast_code = 0 # the message is a broadcast one
private = 1 # this is a private message
new_window = 2 # opening a new chat 
listing_users = 3 # list of users
error_username = 4 # this is only used by server to indicate errors
private_close = 5
close = 6

# authentication-related codes
login1_code = 8
login2_code = 9
login3_code = 10
signup_code = 11
approve_authentication_code = 12
error_authentication_code = 13
close_auth = 14
public_key_code = 15
server_public_code = 16


def decode_msg(data, *args):
    data = json.loads(data)
    img_code = np.asarray(data.get("code"))
    img_user = np.asarray(data.get("user"))
    img_msg = np.asarray(data.get("msg"))
    
    steg_code = LSBSteg(img_code)
    steg_user = LSBSteg(img_user)
    steg_msg = LSBSteg(img_msg)
    
    code = steg_code.decode_text()
    user = steg_user.decode_text()
    msg = steg_msg.decode_text()
    if len(args) != 0:
        shared_key = args[0]
        msg = decrypt_message(msg, shared_key)
    return int(code), user, msg


def encode_msg(code, user, msg, *args):
    if len(args) != 0:
        shared_key = args[0]
        msg = encrypt_message(msg, shared_key)
    img_code = np.random.randint(0, 255, size=(10, 10, 3))
    img_user = np.random.randint(0, 255, size=(30, 30, 3))
    msg_size = len(msg) * 8
    required_size = msg_size
    height = required_size // 4
    width = 4
    img_msg = np.random.randint(0, 255, size=(height, 5 , 3))

    steg_code = LSBSteg(img_code)
    steg_user = LSBSteg(img_user)
    steg_msg = LSBSteg(img_msg)
    
    img_code_encoded = steg_code.encode_text((str(code)))
    img_user_encoded = steg_user.encode_text((user))
    img_msg_encoded = steg_msg.encode_text((msg))
    
    data = json.dumps({"code": img_code_encoded.tolist(),
                       "user": img_user_encoded.tolist(),
                       "msg": img_msg_encoded.tolist()})
    return data.encode()




def generate_private_key():
    return random.getrandbits(16)


def generate_public_key(private_key):
    return (shared_base ** private_key) % shared_prime


def generate_shared_secret(public_key, private_key):
    return (public_key ** private_key) % shared_prime

def get_shared_key(public_key, private_key):
    shared_key = generate_shared_secret(public_key, private_key)
    hashed_shared_key = hashlib.sha256(str(shared_key).encode('utf-8')).hexdigest()
    half_hashed_shared_key = hashed_shared_key[:32]

    half_hashed_shared_key_bytes = bytes(half_hashed_shared_key, encoding='utf-8')

    half_hashed_shared_key_encoded = base64.b64encode(half_hashed_shared_key_bytes)

    return half_hashed_shared_key_encoded


def encrypt_message(private_msg, secret_key):
    secret_key = base64.b64decode(secret_key)
    padding_character = '{'
    cipher = AES.new(secret_key)
    padded_private_msg = private_msg + (padding_character * ((16 - len(private_msg)) % 16))
    encrypted_msg = cipher.encrypt(padded_private_msg)
    encrypted_msg_string = str(base64.b64encode(encrypted_msg))
    return encrypted_msg_string


def decrypt_message(encrypted_msg, secret_key):
    secret_key = base64.b64decode(secret_key)
    encrypted_msg = encrypted_msg.encode('utf-8')
    encrypted_msg = encrypted_msg[2:-1]
    encrypted_msg = base64.b64decode(encrypted_msg)
    padding_character = b'{'
    cipher = AES.new(secret_key)
    decrypted_msg = cipher.decrypt(encrypted_msg)
    unpadded_private_msg = decrypted_msg.rstrip(padding_character)
    decoded_decrypted_msg = unpadded_private_msg.decode('ascii')
    return decoded_decrypted_msg



prime_numbers = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31,
 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
  101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
   157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211,
   223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271,
   277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347,
   349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409,
   419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467,
   479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557,
   563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617,
   619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683,
   691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761,
   769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839,
   853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919,
   929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]


# shared_prime = prime_numbers[random.randrange(len(prime_numbers))]
# shared_base = random.getrandbits(16)
shared_prime = 997
shared_base = 993


dummy_key = b'Qv9CzBTHPar+u2UsDqRiMxKihu56GNJPYc0MghFjsK0='

