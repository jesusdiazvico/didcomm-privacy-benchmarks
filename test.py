# DIDComm imports
import pytest as pytest
import asyncio
import json

from jwcrypto import jwk

from didcomm import (
    Message,
    pack_encrypted,
    PackEncryptedConfig,
    pack_plaintext,
    pack_signed,
#    unpack_forward,
    unpack,
)

import mock_secrets_resolver_alice

from peerdid.dids import (
    create_peer_did_numalgo_0,
    create_peer_did_numalgo_2,
    resolve_peer_did,
    is_peer_did
)

from didcomm.secrets.secrets_resolver_in_memory import SecretsResolverInMemory
from didcomm.common.resolvers import ResolversConfig
from didcomm.secrets.secrets_util import jwk_to_secret

from peerdid.keys import Ed25519VerificationKey, X25519KeyAgreementKey

from pydid.doc import DIDDocument

loop = asyncio.get_event_loop()

VALID_X25519_KEY_AGREEMENT_KEY_1 = X25519KeyAgreementKey.from_base58(
    "JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr"    
)

VALID_X25519_KEY_AGREEMENT_KEY_2 = X25519KeyAgreementKey.from_multibase(
    "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc"
)

VALID_X25519_KEY_AGREEMENT_KEY_JWK_1 = X25519KeyAgreementKey.from_jwk(
    {
        "kty": "OKP",
        "crv": "X25519",
        "x": "BIiFcQEn3dfvB2pjlhOQQour6jXy9d5s2FKEJNTOJik",
    }
)

VALID_ED25519_VERIFICATION_KEY_1 = Ed25519VerificationKey.from_base58(
    "ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7"
)

VALID_ED25519_VERIFICATION_KEY_2 = Ed25519VerificationKey.from_base58(
    "3M5RCDjPTWPkKSN3sxUmmMqHbmRPegYP1tjcKyrDbt9J"
)

#from tests.test_vectors.common import ALICE_DID, BOB_DID, CHARLIE_DID

# DID Peer imports
import json
from typing import Optional

from didcomm.common.types import DID, VerificationMethodType, VerificationMaterial, VerificationMaterialFormat
from didcomm.did_doc.did_doc import DIDDoc, VerificationMethod, DIDCommService
from didcomm.did_doc.did_resolver import DIDResolver
#from peerdid import peer_did
#from peerdid.core.did_doc_types import DIDCommServicePeerDID
#from peerdid.did_doc import DIDDocPeerDID
#from peerdid.types import VerificationMaterialFormatPeerDID

##################

async def create_peerdid(nka, ns):

    kaKeys = []
    sk_kaKeys = []
    for i in range(nka):
        key = jwk.JWK.generate(kty='OKP', crv='X25519')
        sk_kaKeys.append(key.export())
        kaKeys.append(X25519KeyAgreementKey.from_jwk(key.export(private_key=False)))
        #VALID_X25519_KEY_AGREEMENT_KEY_JWK_1)
        
    sKeys = []
    sk_sKeys = []
    for i in range(ns):
        key = jwk.JWK.generate(kty='OKP', crv='Ed25519')
        sk_sKeys.append(key.export())
        sKeys.append(Ed25519VerificationKey.from_jwk(key.export(private_key=False)))
        #VALID_ED25519_VERIFICATION_KEY_1)

    service = {
        "type": "DIDCommMessaging",
        "serviceEndpoint": "https://example.com/endpoint1",
        "routingKeys": ["did:example:somemediator#somekey1"],
        "accept": ["didcomm/v2"],
    }    

    peer_did_algo_2 = create_peer_did_numalgo_2(
        encryption_keys=kaKeys,
        signing_keys=sKeys,
        service=service
    )
    
    assert is_peer_did(peer_did_algo_2)
    return {
        'peerdid': peer_did_algo_2,
        'sk_kaKeys': sk_kaKeys,
        'sk_sKeys': sk_sKeys
        }

#@pytest.mark.asyncio
async def pack_authcrypt(
        sender,
        sender_resolver,
        receiver,
        receiver_resolver,
        mediator,
        mediator_resolver
):
    # ALICE
    msg = Message(
        body={"aaa": 1, "bbb": 2},
        id="1234567890",
        type="my-protocol/1.0",
        frm=sender,
        to=[receiver],
    )
    pack_result = await pack_encrypted(
        resolvers_config=sender_resolver,
        message=msg,
        frm=sender,
        to=receiver,
        pack_config=PackEncryptedConfig(),
    )
    packed_msg = pack_result.packed_msg
    print(f"Sending ${packed_msg} to ${pack_result.service_metadata.service_endpoint}")

    # BOB's MEDIATOR
    forward_recv = await unpack_forward(mediator_resolver, packed_msg, True)
    print(f"Got {forward_bob.forwarded_msg}")

    # BOB
    unpack_result = await unpack(receiver_resolver, forward_recv.forwarded_msg)
    print(f"Got ${unpack_result.message} message")

class DIDResolverPeerDID(DIDResolver):

    async def resolve(self, did: DID) -> Optional[DIDDoc]:
        did_doc = resolve_peer_did(peer_did=did)
        print (json.dumps(did_doc.to_json(), indent=2))
        return did_doc

class MockSecretsResolver(SecretsResolverInMemory):
    def __init__(self, secretsList):
        super().__init__(
            secrets=list(mock_secrets_resolver_alice.MockSecretsResolverAlice()._secrets.values()))

def extend_secrets_list(sl, _sl):
    for s in _sl:
        print(jwk.thumbprint_uri(s))
        sl.append(jwk_to_secret(s))

def main():
    peerdid_1ka_0s = loop.run_until_complete(create_peerdid(1,0))
    peerdid_2ka_0s = loop.run_until_complete(create_peerdid(2,0))
    peerdid_1ka_1s = loop.run_until_complete(create_peerdid(1,1))
    print(resolve_peer_did(peer_did=peerdid_1ka_0s['peerdid']))
    secretsList = []
    extend_secrets_list(secretsList, peerdid_1ka_0s['sk_kaKeys'])
    extend_secrets_list(secretsList, peerdid_1ka_0s['sk_sKeys'])
    extend_secrets_list(secretsList, peerdid_2ka_0s['sk_kaKeys'])
    extend_secrets_list(secretsList, peerdid_2ka_0s['sk_sKeys'])
    extend_secrets_list(secretsList, peerdid_1ka_1s['sk_kaKeys'])
    extend_secrets_list(secretsList, peerdid_1ka_1s['sk_sKeys'])
    print(secretsList)
    
    secretsResolver = MockSecretResolver(secretsList)
    
    resolvers_config = ResolversConfig(mock_secrets_resolver_alice.MockSecretsResolverAlice, DIDResolverPeerDID())
    loop.run_until_complete(pack_authcrypt(peerdid_1ka_0s['peerdid'], resolvers_config,
                                           peerdid_2ka_0s['peerdid'], resolvers_config,
                                           peerdid_1ka_1s['peerdid'], resolvers_config))

if __name__ == "__main__":
    main()
