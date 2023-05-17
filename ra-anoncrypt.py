#!/bin/env python

import sys
import time
import numpy
import json
import secrets

import hashlib

from typing import List
from copy import deepcopy

from authlib.jose import JsonWebEncryption
from authlib.jose.rfc8037 import OKPKey
from authlib.jose.rfc7517 import AsymmetricKey
from authlib.common.encoding import (
    to_unicode,
    to_bytes,
    urlsafe_b64encode,
    json_dumps,
    json_loads,
    json_b64encode,
)
from authlib.jose.rfc7518 import ECDHESAlgorithm, CBCHS2EncAlgorithm

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
    _apv = [ str(ekp.as_dict(is_private=False)) ] # @TODO Check for better ways to encode this
    
    # Encrypt flag per recipient
    for pk in pks:

        # Run ECDH
        shk = ekp.exchange_shared_key(pk.get_public_key())

        # Run KDF to get flag encryption key
        ckdf = ConcatKDFHash(
            algorithm = hashes.SHA256(),
            length=32,
            otherinfo=bytes("ra-anon", "utf-8"),
            backend=default_backend()
        )
        fk = ckdf.derive(shk)

        # Encrypt the flag
        aes = AESCCM(fk)
        nonce = secrets.token_bytes(12)
        aad = bytes("ra-anon", "utf-8")
        c = aes.encrypt(nonce=nonce,
                        data=b'\x01',
                        associated_data=aad)
        _apv.append(str(c)) # @TODO Check for better ways to encode this

    # Base64-encode the _apv array
    apv = to_unicode(
        urlsafe_b64encode(bytes(".".join(sorted(_apv)),'utf-8'))
    )    
        
    header = build_header(pks, apv)

 #    jwe = JsonWebEncryption()

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

    jwe_aad = header_obj.get('aad') # @TODO: we don't pass an aad...
    
    if len(pks) != len(recipients):
        raise ValueError("Count of recipient keys {} does not equal to count of recipients{}"
                         .format(len(pks), len(recipients))) # @TOIMPORT ValueError


    # Step 1: Prepare algorithms and key
    alg = ECDHESAlgorithm()
    enc = CBCHS2EncAlgorithm(256, 512)

    for i in range(len(pks)):
        pks[i] = alg.prepare_key(pks[i])

    # Step 3: Encrypt the CEK
    preset = alg.generate_preset(enc, pks[0])
    if 'cek' in preset:
        cek = preset['cek']
    else:
        cek = None

    if len(pks) > 1 and cek is None:
        raise InvalidAlgorithmForMultipleRecipientsMode(alg.name) # @TOIMPORT
    if 'header' in preset:
        shared_header.update_protected(preset['header'])

    # This is a tag-aware key agreement, so delaying CEK encryption...
    epks = []
    print("Remember to check that the previously computed ekp is used here.")
    for i in range(len(pks)):

        # prep = enc.generate_keys_and_prepare_headers(pks[i], None, preset)
        if preset and 'epk' in preset:
            epk = preset['epk']
            h = {}
        else:
            epk = pks[i].generate_key(key['crv'], is_private=True)
            pub_epk = {k: epk[k] for k in epk.REQUIRED_JSON_FIELDS}
            pub_epk['kty'] = epk.kty
            h = {'epk': pub_epk }

        if preset and 'cek' in preset:
            cek = preset['cek']
        else:
            cek = enc.generate_cek()

        prep = { 'epk': epk, 'cek': cek, 'header': h }
        
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
    print(msg)
    _msg = encode(msg)

    # Step 7: Perform encryption
    ciphertext, tag = enc.encrypt(_msg, aad, iv, cek)

    # Run the delayed CEK encryption
    for i in range(len(pks)):
        wrapped = enc.agree_upon_key_and_wrap_cek(shared_header,
                                                  pks[i],
                                                  None,
                                                  epks[i],
                                                  cek,
                                                  tag)
        recipients[i]['encrypted_key'] = wrapped['ek']

    # Step 8: Build resulting message
    obj = OrderedDict()

    if shared_header.protected:
        obj['protected'] = to_unicode(json-b64encode(shared_header.protected))

    if shared_header.unprotected:
        obj['unprotected'] = shared_header.unprotected

    for r in recipients:
        if not r['header']:
            del r['header']
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
#        dec_json = anondecrypt(ctxt, recipients)
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
