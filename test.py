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
    is_peer_did,
)

from didcomm.secrets.secrets_resolver_in_memory import SecretsResolverInMemory
from didcomm.secrets.secrets_resolver_demo import SecretsResolverDemo
from didcomm.secrets.secrets_util import (
    jwk_to_secret,
    generate_ed25519_keys_as_jwk_dict,
    generate_x25519_keys_as_jwk_dict    
)
from didcomm.common.resolvers import ResolversConfig

from peerdid.keys import (
    Ed25519VerificationKey,
    X25519KeyAgreementKey,
    BaseKey,
    to_multibase
)

from pydid.doc import DIDDocument

loop = asyncio.get_event_loop()

# DID Peer imports
import json
from typing import Optional

from didcomm.common.types import DID, VerificationMethodType, VerificationMaterial, VerificationMaterialFormat
from didcomm.did_doc.did_doc import DIDDoc, VerificationMethod, DIDCommService
from didcomm.did_doc.did_resolver import DIDResolver

##################

#
def update_secrets_kids(in_kaKeys, in_sKeys, peerdid):
    
    chunks = peerdid[13:].split('.')
    ctr = 0
    out_kaKeys = []
    for jk in in_kaKeys:
        k = json.loads(jk)
        k['kid'] = "#"+chunks[ctr][:8:]
        ctr+=1
        out_kaKeys.append(json.dumps(k))
        
    out_sKeys = []
    for jk in in_sKeys:
        k = json.loads(jk)
        k['kid'] = "#"+chunks[ctr][:8:]
        ctr+=1
        out_sKeys.append(json.dumps(k))

    return [out_kaKeys, out_sKeys]

async def create_peerdid(nka, ns):

    kaKeys = []
    in_kaKeys = []
    for i in range(nka):
        key = generate_x25519_keys_as_jwk_dict()[0]
        in_kaKeys.append(json.dumps(key))
        kaKeys.append(X25519KeyAgreementKey.from_jwk(key))
        
    sKeys = []
    in_sKeys = []
    for i in range(ns):
        key = generate_ed25519_keys_as_jwk_dict()[0]
        in_sKeys.append(json.dumps(key))
        sKeys.append(Ed25519VerificationKey.from_jwk(key))

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

    # This is a very dirty way to update the 'kid' of the Secrets.
    # There must be a better way
    [sk_kaKeys, sk_sKeys] = update_secrets_kids(in_kaKeys, in_sKeys, peer_did_algo_2)
    
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
        return DIDDoc(
            id=did_doc.id,
            authentication=did_doc.authentication,
            key_agreement=did_doc.key_agreement,
            verification_method=did_doc.verification_method,
#            service=DIDCommService(did_doc.service)
        )

class MockSecretsResolver(SecretsResolverInMemory):
    def __init__(self, secretsList):
        super().__init__(
            secrets=list(mock_secrets_resolver_alice.MockSecretsResolverAlice()._secrets.values()))

def main():

    # Create sample DIDs
    peerdid_1ka_0s = loop.run_until_complete(create_peerdid(1,0))
    peerdid_2ka_0s = loop.run_until_complete(create_peerdid(2,0))
    peerdid_1ka_1s = loop.run_until_complete(create_peerdid(1,1))    

    # Create custom resolver
    secrets_resolver = SecretsResolverDemo()
    for s in peerdid_1ka_0s['sk_kaKeys']:
        loop.run_until_complete(secrets_resolver.add_key(jwk_to_secret(json.loads(s))))
    for s in peerdid_1ka_0s['sk_sKeys']:
        loop.run_until_complete(secrets_resolver.add_key(jwk_to_secret(json.loads(s))))
    for s in peerdid_2ka_0s['sk_kaKeys']:
        loop.run_until_complete(secrets_resolver.add_key(jwk_to_secret(json.loads(s))))
    for s in peerdid_2ka_0s['sk_sKeys']:
        loop.run_until_complete(secrets_resolver.add_key(jwk_to_secret(json.loads(s))))
    for s in peerdid_1ka_1s['sk_kaKeys']:
        loop.run_until_complete(secrets_resolver.add_key(jwk_to_secret(json.loads(s))))
    for s in peerdid_1ka_0s['sk_sKeys']:
        loop.run_until_complete(secrets_resolver.add_key(jwk_to_secret(json.loads(s))))
    resolvers_config = ResolversConfig(secrets_resolver, DIDResolverPeerDID())

    # Authcrypt packaging
    loop.run_until_complete(pack_authcrypt(peerdid_1ka_0s['peerdid'], resolvers_config,
                                           peerdid_2ka_0s['peerdid'], resolvers_config,
                                           peerdid_1ka_1s['peerdid'], resolvers_config))

if __name__ == "__main__":
    main()
