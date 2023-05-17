#!/bin/env python

import sys
import time
import numpy
import json
import secrets
import random

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
from authlib.jose.util import (
    ensure_dict,
    extract_header,
    extract_segment
)
from authlib.jose.rfc8037 import OKPKey
from authlib.jose.errors import DecodeError

from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
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

# This is pretty much as in didcomm-python's anoncrypt.py
def build_header(to: List[AsymmetricKey], apv):
    # Toy example: making up the kids
    kids = list(map(lambda i: "did:example:bob#key"+str(i), range(len(to))))
    protected = {
        "typ": 'application/didcomm-encrypted+json', # Defined in Sec 2.4 of DIDComm v2 spec
        "alg": 'ECDH-ES+A256KW', # Defined in Sec 5.1.4 of DIDComm v2 spec
        "enc": 'A256CBC-HS512', # Defined in Sec 5.1.3 of DIDComm v2 spec
        "apv": apv,
    }
    recipients = [{"header": {"kid": kid}} for kid in kids]
    return {"protected": protected, "recipients": recipients}

def raanoncrypt(msg, pks):

    # Compute ephemeral key pair for flagging
    ekp = gen_keys(1)[0]
    _apv = {}    
    _apv['ekp'] = ekp.as_dict(is_private=False)
    
    # Encrypt flag per recipient
    flags = []
    for pk in pks:

        # Run ECDH
        shk = ekp.exchange_shared_key(pk.get_public_key())

        # Run KDF to get flag encryption key
        ckdf = ConcatKDFHash(
            algorithm = hashes.SHA256(),
            length = 32,
            otherinfo = bytes("ra-anon", "utf-8"),
            backend = default_backend()
        )
        fk = ckdf.derive(shk)

        # Encrypt the flag
        aes = AESCCM(fk)
        nonce = secrets.token_bytes(12)
        aad = bytes("ra-anon", "utf-8")
        c = aes.encrypt(nonce=nonce,
                        data=b'\x01',
                        associated_data=aad)
        flags.append([
            urlsafe_b64encode(c).decode('utf-8'),
            urlsafe_b64encode(nonce).decode('utf-8'),
        ])

    # Base64-encode the _apv array
    _apv['flags'] = flags
    apv = to_unicode(urlsafe_b64encode(json.dumps(_apv).encode('utf-8')))
        
    header = build_header(pks, apv)

    ## From here on, we essentially copy the serialize_json function in
    ## authlib.jose.rfc7516.jwe, but reusing the ekp computed above, and
    ## ommitting some instructions aimed at achieving a generality that we
    ## don't need for this PoC

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
    alg = ECDHESAlgorithm(256)
    enc = CBCHS2EncAlgorithm(256, 512)

    for i in range(len(pks)):
        pks[i] = alg.prepare_key(pks[i])

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

    # This is not a tag-aware key agreement, so not delaying CEK encryption...
    for i in range(len(pks)):
        wrapped = alg.wrap(enc, shared_header, pks[i], preset)
        if cek is None:
            cek = wrapped['cek']        
        recipients[i]['encrypted_key'] = wrapped['ek']
        if 'header' in wrapped:
            recipients[i]['header'].update(wrapped['header'])
    
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

    # Step 8: Build resulting message
    obj = OrderedDict()

    if shared_header.protected:
        obj['protected'] = to_unicode(json_b64encode(shared_header.protected))

    if shared_header.unprotected:
        obj['unprotected'] = shared_header.unprotected

    for r in recipients:
        del r['header'] # Anonymous receivers, we don't want kids
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

def raanondecrypt(ctxt, sks):

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

    alg = ECDHESAlgorithm(256)
    enc = CBCHS2EncAlgorithm(256, 512)
    key = alg.prepare_key(sks[0])
    kid = "did:example:bob#key0" # In our PoC, we always decrypt with Bob's first key
    
    # Parse apv for potential matches
    apv = extract_segment(to_bytes(protected['apv']), DecodeError, 'apv').decode('utf-8')

    ## Retrieve the ekp
    ekp = OKPKey.import_dict_key(json.loads(apv)['ekp'])

    ## Trial-decrypt the flags
    flags = json.loads(apv)['flags']

    # For simulation purposes, pick "randomly" one key within the array
    # this makes the trial decryption more realistic
    rnd = random.randint(0,len(sks)-1)
    key = sks[rnd]
    match = False
    i = 0
    index = 0
    for fn in flags:
        flag = fn[0]
        nonce = fn[1]
        shk = key.exchange_shared_key(ekp.get_public_key())
        ckdf = ConcatKDFHash(
            algorithm = hashes.SHA256(),
            length = 32,
            otherinfo = bytes("ra-anon", "utf-8"),
            backend = default_backend()
        )
        fk = ckdf.derive(shk)
        aes = AESCCM(fk)
        f = aes.decrypt(nonce=urlsafe_b64decode(bytes(nonce, "utf-8")),
                        data=urlsafe_b64decode(bytes(flag, "utf-8")),
                        associated_data=bytes("ra-anon", "utf-8"))
        if f == b'\x01':
            match = True
            index = i
            break

        i = i+1

    if match == False:
        return None    
    
    # If we reach this point, there was a match in the encrypted flags, so
    # go get the cek
    ek = ctxt['recipients'][index]['encrypted_key']
    header = JWEHeader(protected, unprotected, {})
    cek = alg.unwrap(enc, ek, header, key)


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
    iters = int(sys.argv[3])

    # Generate recipients' key pairs
    recipients = gen_keys(n_recipients)

    # Run tests iters times
    anoncrypt_times = []
    anondecrypt_times = []
    sizes = []

    msg_json = { 'data': msg }
    for i in range(iters):

        # Measure time for anoncrypting
        st_crypt = time.process_time()
        ctxt = raanoncrypt(msg_json, recipients)
        et_crypt = time.process_time()
        anoncrypt_times.append(et_crypt - st_crypt)
        sizes.append(sys.getsizeof(json.dumps(ctxt)))

        # Measure time for "anondecrypting"
        st_decrypt = time.process_time()
        dec_json = raanondecrypt(ctxt, recipients)
        if dec_json == None:
            print("Unexpected mismatch.")
            return
        et_decrypt = time.process_time()
        anondecrypt_times.append(et_decrypt - st_decrypt)

    anoncrypt_avg = numpy.average(anoncrypt_times)
    anoncrypt_std = numpy.std(anoncrypt_times)
    anondecrypt_avg = numpy.average(anondecrypt_times)
    anondecrypt_std = numpy.std(anondecrypt_times)
    sizes_avg = numpy.average(sizes)
    sizes_std = numpy.std(sizes)

    print("{}\t{}\t{}\t{}\t{}\t{}\t{}"
        .format(n_recipients,
                anoncrypt_avg,
                anoncrypt_std,
                anondecrypt_avg,
                anondecrypt_std,
                sizes_avg,
                sizes_std)
          )
    
    return

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage ./anoncrypt <msg> <num. recipients> <iters>")
        sys.exit()
    main()
