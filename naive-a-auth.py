#!/bin/env python

import sys
import time
import numpy
import json

import hashlib

from typing import List

from authlib.jose import JsonWebEncryption
from authlib.jose.rfc8037 import OKPKey
from authlib.jose.rfc7517 import AsymmetricKey
from authlib.common.encoding import (
    to_unicode,
    to_bytes,
    urlsafe_b64encode,
    json_dumps,
    json_loads,
)
from authlib.jose.drafts import register_jwe_draft
from authlib.jose.util import extract_header
from authlib.jose.errors import DecodeError

def encode(msg):
    return to_bytes(json_dumps(msg))

def decode(msg):
    return json_loads(msg)

def gen_keys(n):
    keys = []
    for i in range(n):
        k = OKPKey.generate_key(crv='X25519',is_private=True)
        keys.append(k)
    return keys

def calculate_apv(kids):
    return to_unicode(
        urlsafe_b64encode(hashlib.sha256(to_bytes(".".join(sorted(kids)))).digest())
    )    

# This is pretty much as in didcomm-python's authcrypt.py
def build_header_authcrypt(to: List[AsymmetricKey]):
    # Toy example: making up the kids
    kids = list(map(lambda i: "did:example:bob#key"+str(i), range(len(to))))    
    apv = calculate_apv(kids)
    protected = {
        "typ": "application/didcomm-encrypted+json",
        "alg": "ECDH-1PU+A256KW",
        "enc": "A256CBC-HS512",
        "apu": to_unicode(urlsafe_b64encode(to_bytes("did:example:alice#key0"))),
        "apv": apv,
        "skid": "did:example:alice#key0",
    }
    recipients = [{"header": {"kid": kid}} for kid in kids]
    return {"protected": protected, "recipients": recipients}

def authcrypt(msg, pks, sk):
    header = build_header_authcrypt(pks)
    jwe = JsonWebEncryption()
    ctxt = jwe.serialize_json(header, encode(msg), pks, sender_key=sk)
    return ctxt

def authdecrypt(ctxt, sks, sender):
    header = build_header_authcrypt(sks)
    jwe = JsonWebEncryption()
    # For testing purposes, we only decrypt with the first recpient's key
    dec = decode(jwe.deserialize_json(ctxt,sks[0], sender_key=sender)['payload'])
    return dec

# This is pretty much as in didcomm-python's anoncrypt.py
def build_header_anoncrypt(to: List[AsymmetricKey]):
    # Toy example: making up the kids
    kids = list(map(lambda i: "did:example:bob#key"+str(i), range(len(to))))
    apv = calculate_apv(kids)
    protected = {
        "typ": 'application/didcomm-encrypted+json', # Defined in Sec 2.4 of DIDComm v2 spec
        "alg": 'ECDH-ES+A256KW', # Defined in Sec 5.1.4 of DIDComm v2 spec
        "enc": 'A256CBC-HS512', # Defined in Sec 5.1.3 of DIDComm v2 spec
        "apv": apv,
    }
    recipients = [{"header": {"kid": kid}} for kid in kids]
    return {"protected": protected, "recipients": recipients}

def anoncrypt(msg, pks):
    header = build_header_anoncrypt(pks)
    jwe = JsonWebEncryption()
    ctxt = jwe.serialize_json(header, encode(msg), pks)
    return ctxt

def anondecrypt(ctxt, sks):
    header = build_header_authcrypt(sks)
    jwe = JsonWebEncryption()
    # For testing purposes, we only decrypt with the first recpient's key
    dec = decode(jwe.deserialize_json(ctxt,sks[0])['payload'])
    return dec

def aauthcrypt(msg, pks, sk):
    ctxt_authcrypt = authcrypt(msg, pks, sk)
    ctxt_aauthcrypt = anoncrypt(ctxt_authcrypt, pks)
    return ctxt_aauthcrypt

def aauthdecrypt(ctxt, sks, sender):
    ctxt_authcrypt = anondecrypt(ctxt, sks)
    msg = authdecrypt(ctxt_authcrypt, sks, sender)
    return msg

def main():

    # Parse params
    msg = sys.argv[1]
    n_recipients = int(sys.argv[2])

    debug = False
    if sys.argv[3] == "debug":
        debug = True
        iters = 1
    else:
        iters = int(sys.argv[3])
    
    # Generate key pairs
    sender = gen_keys(1)[0]
    recipients = gen_keys(n_recipients)

    # Run tests iters times
    aacrypt_times = []
    aadecrypt_times = []
    sizes = []
    for i in range(iters):

        # Measure time for "crypting"
        st_crypt = time.process_time()
        ctxt = aauthcrypt(msg, recipients, sender)
        et_crypt = time.process_time()
        aacrypt_times.append(et_crypt - st_crypt)
        sizes.append(sys.getsizeof(json.dumps(ctxt)))

        if debug:
            prot = extract_header(to_bytes(ctxt['protected']), DecodeError)
            unprot = ctxt.get('unprotected')
            print("Full DIDComm message:")
            print(json.dumps(ctxt, indent=2))
            print("protected header:")
            print(json.dumps(prot, indent=2))
            print("unprotected header:")
            print(json.dumps(unprot, indent=2)) if unprot else print("None")

        # Measure time for "decrypting"
        st_decrypt = time.process_time()
        dec = aauthdecrypt(ctxt, recipients, sender)
        et_decrypt = time.process_time()
        aadecrypt_times.append(et_decrypt - st_decrypt)

    crypt_avg = numpy.average(aacrypt_times)
    crypt_std = numpy.std(aacrypt_times)
    decrypt_avg = numpy.average(aadecrypt_times)
    decrypt_std = numpy.std(aadecrypt_times)
    sizes_avg = numpy.average(sizes)
    sizes_std = numpy.std(sizes)

    print("{}\t{}\t{}\t{}\t{}\t{}\t{}"
        .format(n_recipients,
                crypt_avg,
                crypt_std,
                decrypt_avg,
                decrypt_std,
                sizes_avg,
                sizes_std)
          )
    
    return

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage ./naive-a-auth <msg> <num. recipients> <iters>")
        sys.exit()
    register_jwe_draft(JsonWebEncryption)
    main()
