#!/bin/env python

import sys
import time
import numpy
import json
import secrets
import os

import hashlib

from typing import List
from copy import deepcopy
from collections import OrderedDict

from authlib.jose import JsonWebEncryption
from authlib.jose.rfc7516.models import JWEHeader
from authlib.jose.rfc7517 import AsymmetricKey
from authlib.common.encoding import (
    to_unicode,
    to_bytes,
    urlsafe_b64encode,
    urlsafe_b64decode,
    json_dumps,
    json_loads,
    json_b64encode,
)
from authlib.jose.rfc7518 import ECDHESAlgorithm, CBCHS2EncAlgorithm
from authlib.jose.drafts import register_jwe_draft
from authlib.jose.drafts._jwe_algorithms import ECDH1PUAlgorithm
from authlib.jose.util import (
    ensure_dict,
    extract_header,
    extract_segment
)
from authlib.jose.rfc8037 import OKPKey
from authlib.jose.errors import DecodeError

from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

#####
# Dirty hack: copy-pasted from authlib.jose.rfc7516.models.py
####

class JWESharedHeader(dict):
    """Shared header object for JWE.

    Combines protected header and shared unprotected header together.
    """
    def __init__(self, protected, unprotected):
        obj = {}
        if protected:
            obj.update(protected)
        if unprotected:
            obj.update(unprotected)
        super(JWESharedHeader, self).__init__(obj)
        self.protected = protected if protected else {}
        self.unprotected = unprotected if unprotected else {}

    def update_protected(self, addition):
        self.update(addition)
        self.protected.update(addition)

    @classmethod
    def from_dict(cls, obj):
        if isinstance(obj, cls):
            return obj
        return cls(obj.get('protected'), obj.get('unprotected'))

#####

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
    l = sorted(kids)
    l.insert(0,"a-auth")
    _apv = ".".join(l)
    return to_unicode(
        urlsafe_b64encode(hashlib.sha256(to_bytes(_apv)).digest())
    ) 

# This is pretty much as in didcomm-python's anoncrypt.py
def build_header(to: List[AsymmetricKey]):
    # Toy example: making up the kids
    kids = list(map(lambda i: "did:example:bob#key"+str(i), range(len(to))))
    apv = calculate_apv(kids)
    protected = {
        "typ": 'application/didcomm-encrypted+json', # Defined in Sec 2.4 of DIDComm v2 spec
        "alg": 'ECDH-ES-1PU+A256KW', # New mode
        "enc": 'A256CBC-HS512', # Defined in Sec 5.1.3 of DIDComm v2 spec
        "apv": apv,
    }
    recipients = [{"header": {"kid": kid}} for kid in kids]
    return {"protected": protected, "recipients": recipients}

def mergeaacrypt(msg, pks, sk):

    header = build_header(pks)

    if not isinstance(pks, list): pks = [pks]
    header_obj = deepcopy(header)
    shared_header = JWESharedHeader.from_dict(header_obj)

    recipients = header_obj.get('recipients')
    for i in range(len(recipients)):
        if 'header' not in recipients[i]:
            recipients[i]['header'] = {}

    jwe_aad = header_obj.get('aad')
    
    if len(pks) != len(recipients):
        raise ValueError("Count of recipient keys {} does not equal to count of recipients{}"
                         .format(len(pks), len(recipients)))


    # Step 1: Prepare algorithms and key
    alg = ECDH1PUAlgorithm(256)
    enc = CBCHS2EncAlgorithm(256, 512)

    for i in range(len(pks)):
        pks[i] = alg.prepare_key(pks[i])

    sender_key = alg.prepare_key(sk)

    # Step 3: Encrypt the CEK
    preset = alg.generate_preset(enc, pks[0])

    if 'cek' in preset:
        cek = preset['cek']
    else:
        cek = None

#    if len(pks) > 1 and cek is None:
#        raise ValueError("InvalidAlgorithmForMultipleRecipientsMode {}"
#                         .format(alg.name))
    if 'header' in preset:
        shared_header.update_protected(preset['header'])

    # This is a tag-aware key agreement...
    epks = []
    for i in range(len(pks)):
        prep = alg.generate_keys_and_prepare_headers(enc, pks[i], sender_key, preset)
        if cek is None:
            cek = prep['cek']
        epks.append(prep['epk'])
        recipients[i]['header'].update(prep['header'])
    
    # Step 4: Generate a random JWE Initialization Vector
    iv = enc.generate_iv()

    # Step 5: Compute the Encoded Protected Header Value
    aad = json_b64encode(shared_header.protected) if shared_header.protected else b''
    if jwe_aad is not None:
        aad += b'.' + urlsafe_b64encode(jwe_aad)
    aad = to_bytes(aad, 'ascii')

    # Step 6: No compression
    _msg = encode(msg)

    # Step 7: Perform encryption
    ciphertext, tag = enc.encrypt(_msg, aad, iv, cek)

    # Delayed CEK encryption
    for i in range(len(pks)):
        wrapped = alg.agree_upon_key_and_wrap_cek(
            enc,
            shared_header,
            pks[i],
            sender_key,
            epks[i],
            cek,
            tag)
        recipients[i]['encrypted_key'] = wrapped['ek']

        # Addition: We re-encrypt each ek with an additional layer, including
        # the sender's identity
        # Run ECDH
        shk = epks[i].exchange_shared_key(pks[i].get_public_key())

        # Run KDF to get key re-encryption key
        kids = list(map(lambda i: "did:example:bob#key"+str(i), range(len(pks))))
        _oi = sorted(kids)
        _oi.insert(0,"a-auth")
        _oi.append(to_unicode(urlsafe_b64encode(to_bytes(tag))))
        oi = ".".join(_oi)
        ckdf = ConcatKDFHash(
            algorithm = hashes.SHA256(),
            length = 32,
            otherinfo = bytes(oi, "utf-8"),
            backend = default_backend()
        )
        eek = ckdf.derive(shk)

        # Re-encrypt the ek
        iv_eek = os.urandom(16)
        enc_eek = Cipher(algorithms.AES(eek), modes.CTR(iv_eek))
        encryptor_eek = enc_eek.encryptor()
        data = ".".join(
            (
                "a-auth",
                "did:example:alice#key0",
                urlsafe_b64encode(wrapped['ek']).decode('utf-8')
            )
        )
        ct = encryptor_eek.update(to_bytes(data)) + encryptor_eek.finalize()

        recipients[i]['encrypted_key'] = iv_eek + ct

    # Step 8: Build resulting message
    obj = OrderedDict()

    if shared_header.protected:
        obj['protected'] = to_unicode(json_b64encode(shared_header.protected))

    if shared_header.unprotected:
        obj['unprotected'] = shared_header.unprotected

    for r in recipients:
        #del r['header'] # Anonymous receivers, we don't want kids
        r['encrypted_key'] = to_unicode(urlsafe_b64encode(r['encrypted_key']))
        for member in set(r.keys()):
            if member not in {'header', 'encrypted_key'}:
                del r[member]
    obj['recipients'] = recipients

    if jwe_aad is not None:
        obj['aad'] = to_unicode(urlsafe_b64encode(jwe_aad))

    obj['iv'] = to_unicode(urlsafe_b64encode(iv))
    obj['ciphertext'] = to_unicode(urlsafe_b64encode(ciphertext))
    obj['tag'] = to_unicode(urlsafe_b64encode(tag))

    return obj

# Sender should not be received here. Adding for testing purposes.
# In reality, the sender key should be "resolved" once the sender identifier
# is decrypted.
def mergeaadecrypt(ctxt, sks, sender_pk):

    # First, parse header as in deserialize_json@authlib.jose.rfc7516.jwe.py
    ctxt = ensure_dict(ctxt, 'JWE')
    ctxt = deepcopy(ctxt)

    if 'protected' in ctxt:
        protected = extract_header(to_bytes(ctxt['protected']), DecodeError)
    else:
        protected = None

    unprotected = ctxt.get('unprotected')

    recipients = ctxt['recipients']
    for r in recipients:
        if 'header' not in r:
            r['header'] = {}
        r['encrypted_key'] = extract_segment(
            to_bytes(r['encrypted_key']), DecodeError, 'encrypted key'
        )

    if 'aad' in ctxt:
        jwe_aad = extract_segment(to_bytes(ctxt['aad']), DecodeError, 'JWE AAD')
    else:
        jwe_aad = None

    iv = extract_segment(
        to_bytes(ctxt['iv']), DecodeError, 'iv')    
    ciphertext = extract_segment(to_bytes(ctxt['ciphertext']), DecodeError, 'ciphertext')
    tag = extract_segment(to_bytes(ctxt['tag']), DecodeError, 'tag')
    shared_header = JWESharedHeader(protected, unprotected)

    alg = ECDH1PUAlgorithm(256)
    enc = CBCHS2EncAlgorithm(256, 512)
    key = alg.prepare_key(sks[0])
    kid = "did:example:bob#key0" # In our PoC, we always decrypt with Bob's first key

    epk = key.import_key(shared_header['epk'])
    epk_pubkey = epk.get_op_key('wrapKey')
        
    # Addition: We need to peel off the first layer of key encryption, to get
    # the sender's identity
    
    # Run ECDH
    shk = sks[0].exchange_shared_key(epk_pubkey)

    # Run KDF to get flag encryption key
    kids = list(map(lambda i: "did:example:bob#key"+str(i), range(len(recipients))))
    _oi = sorted(kids)
    _oi.insert(0,"a-auth")
    _oi.append(to_unicode(urlsafe_b64encode(to_bytes(tag))))
    oi = ".".join(_oi)
    ckdf = ConcatKDFHash(
        algorithm = hashes.SHA256(),
        length = 32,
        otherinfo = bytes(oi, "utf-8"),
        backend = default_backend()
    )
    edk = ckdf.derive(shk)

    # Re-encrypt the ek
    iv_eek = ctxt['recipients'][0]['encrypted_key'][0:16]
    ct = ctxt['recipients'][0]['encrypted_key'][16:]

    dec_eek = Cipher(algorithms.AES(edk), modes.CTR(iv_eek))
    decryptor_eek = dec_eek.decryptor()
    data = decryptor_eek.update(ct) + decryptor_eek.finalize()

    chunks = data.decode('utf-8').split(".")
    if len(chunks) != 3:
        raise ValueError("Wrong decryption of CEK (unexpected number of chunks).")

    if chunks[0] != "a-auth":
        raise ValueError("Wrong decryption of CEK (invalid first chunk).")

    if chunks[1] != "did:example:alice#key0": # Hardcoded key id for testing purpose
        raise ValueError("Wrong decryption of CEK (invalid second chunk).")

    ek = urlsafe_b64decode(to_bytes(chunks[2]))

    header = JWEHeader(protected, unprotected, ctxt['recipients'][0]['header'])

    # Hack: instead of resolving the sender_pk from the chunks[1] identifier, we
    # receive it as a param -- this is only for testing purposes!
    sender_key = alg.prepare_key(sender_pk)
    cek = alg.unwrap(enc, ek, header, key, sender_key, tag)

    # Decrypt the actual payload
    aad = to_bytes(ctxt.get('protected', ''))
    if 'aad' in ctxt:
        aad += b'.' + to_bytes(obj['aad'])
    aad = to_bytes(aad, 'ascii')

    dec = enc.decrypt(ciphertext, aad, iv, tag, cek)

    h = {}
    if protected:
        h['protected'] = protected
    if unprotected:
        h['unprotected'] = unprotected
    if jwe_aad is not None:
        header['aad'] = jwe_aad

    return {
        'header': h,
        'payload': decode(dec)
    }

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
    crypt_times = []
    decrypt_times = []
    sizes = []

    msg_json = { 'data': msg }
    for i in range(iters):

        # Measure time for "crypting"
        st_crypt = time.process_time()
        ctxt = mergeaacrypt(msg_json, recipients, sender)
        et_crypt = time.process_time()
        crypt_times.append(et_crypt - st_crypt)
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
        dec_json = mergeaadecrypt(ctxt, recipients, sender)
        if dec_json == None:
            print("Unexpected mismatch.")
            return
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
        print("Usage ./merge-a-auth <msg> <num. recipients> <iters>")
        sys.exit()
    register_jwe_draft(JsonWebEncryption)        
    main()
