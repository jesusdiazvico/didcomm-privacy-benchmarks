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

# This is pretty much as in didcomm-python's anoncrypt.py
def build_header(to: List[AsymmetricKey]):
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
    header = build_header(pks)
    jwe = JsonWebEncryption()
    ctxt = jwe.serialize_json(header, encode(msg), pks)
    return ctxt

def anondecrypt(ctxt, sks):
    header = build_header(sks)
    jwe = JsonWebEncryption()
    # For testing purposes, we only decrypt with the first recpient's key
    dec = decode(jwe.deserialize_json(ctxt,sks[0])['payload'])
    return dec

def main():

    # Parse params
    msg = sys.argv[1]
    n_recipients = int(sys.argv[2])
    iters = int(sys.argv[3])

    # Generate recipients' key pairs
    recipients = gen_keys(n_recipients)

    # Run tests iters times
    crypt_times = []
    decrypt_times = []
    sizes = []

    msg_json = { 'data': msg }
    for i in range(iters):

        # Measure time for anoncrypting
        st_crypt = time.process_time()
        ctxt = anoncrypt(msg_json, recipients)
        et_crypt = time.process_time()
        crypt_times.append(et_crypt - st_crypt)
        sizes.append(sys.getsizeof(json.dumps(ctxt)))

        # Measure time for "anondecrypting"
        st_decrypt = time.process_time()
        dec_json = anondecrypt(ctxt, recipients)
        et_decrypt = time.process_time()
        decrypt_times.append(et_decrypt - st_decrypt)

    crypt_avg = numpy.average(crypt_times)
    crypt_std = numpy.std(crypt_times)
    decrypt_avg = numpy.average(decrypt_times)
    decrypt_std = numpy.std(decrypt_times)
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
        print("Usage ./anoncrypt <msg> <num. recipients> <iters>")
        sys.exit()
    main()
