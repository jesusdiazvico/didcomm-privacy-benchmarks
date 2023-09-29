#!/bin/env python

import sys
import time
import numpy
import json

import hashlib

from resource import *

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
def build_header(to: List[AsymmetricKey]):
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
    header = build_header(pks)
    jwe = JsonWebEncryption()
    ctxt = jwe.serialize_json(header, encode(msg), pks, sender_key=sk)
    return ctxt

def authdecrypt(ctxt, sks, sender):
    header = build_header(sks)
    jwe = JsonWebEncryption()
    # For testing purposes, we only decrypt with the first recpient's key
    dec = decode(jwe.deserialize_json(ctxt,sks[0], sender_key=sender)['payload'])
    return dec

def main():

    # Parse params
    msg = sys.argv[1]
    n_recipients = int(sys.argv[2])

    # Generate key pairs
    sender = gen_keys(1)[0]
    recipients = gen_keys(n_recipients)

    # Measure authcrypting memory usage
    msg_json = { 'data': msg }
    ctxt = authcrypt(msg, recipients, sender)
    mem_self = getrusage(RUSAGE_SELF)
    mem_child = getrusage(RUSAGE_CHILDREN)
    print("{}".format(mem_self[2]+mem_child[2]))
    
    return

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage ./authcrypt <msg> <num. recipients>")
        sys.exit()
    register_jwe_draft(JsonWebEncryption)
    main()
