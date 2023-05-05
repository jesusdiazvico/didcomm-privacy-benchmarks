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

async def create_peerdid(nka, ns, mediator=None):

    kaKeys = []
    for i in range(nka):
        key = generate_x25519_keys_as_jwk_dict()[0]
        kaKeys.append(key)
        
    sKeys = []
    for i in range(ns):
        key = generate_ed25519_keys_as_jwk_dict()[0]
        sKeys.append(key)

    if mediator == None:
        m = []
        s = "https://example.com/endpoint1"
    else:
        did_doc = resolve_peer_did(peer_did=mediator)
        m = [str(mediator)+"#"+str(did_doc.verification_method[0].id)]
        s = str(mediator)+"#"+str(did_doc.verification_method[0].id)
        
    service = {
        "type": "did-communication",
        "serviceEndpoint": s,
        "routingKeys": m,
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
        'sk_kaKeys': in_kaKeys,
        'sk_sKeys': in_sKeys
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
            key_agreement=did_doc.Key_agreement,#list(map(lambda kid: str(did)+kid, did_doc.key_agreement)), #did_doc.key_agreement,
            verification_method=did_doc.verification_method,
            service=[DIDCommService(
                id=did_doc.service[0].id,
                type=did_doc.service[0].type,
                service_endpoint=did_doc.service[0].service_endpoint,
                accept=did_doc.service[0].accept,
                routing_keys=did_doc.service[0].routingKeys,
                recipient_keys=[]
            )]
        )

def main():

    # Create sample DIDs
    peerdid_mediator = loop.run_until_complete(create_peerdid(1,1))
    peerdid_sender = loop.run_until_complete(create_peerdid(1,1,peerdid_mediator['peerdid']))
    peerdid_receiver = loop.run_until_complete(create_peerdid(2,0,peerdid_mediator['peerdid']))

    print("MEDIATOR DID")
    print(resolve_peer_did(peerdid_mediator['peerdid']))

    print("SENDER DID")
    print(resolve_peer_did(peerdid_sender['peerdid']))

    print("RECEIVER DID")
    print(resolve_peer_did(peerdid_receiver['peerdid']))

    # Create custom resolver
    secrets_resolver = SecretsResolverDemo()
    for s in peerdid_mediator['sk_kaKeys']:
        loop.run_until_complete(secrets_resolver.add_key(jwk_to_secret(json.loads(s))))
    for s in peerdid_mediator['sk_sKeys']:
        loop.run_until_complete(secrets_resolver.add_key(jwk_to_secret(json.loads(s))))
    for s in peerdid_sender['sk_kaKeys']:
        loop.run_until_complete(secrets_resolver.add_key(jwk_to_secret(json.loads(s))))
    for s in peerdid_sender['sk_sKeys']:
        loop.run_until_complete(secrets_resolver.add_key(jwk_to_secret(json.loads(s))))
    for s in peerdid_receiver['sk_kaKeys']:
        loop.run_until_complete(secrets_resolver.add_key(jwk_to_secret(json.loads(s))))
    for s in peerdid_receiver['sk_sKeys']:
        loop.run_until_complete(secrets_resolver.add_key(jwk_to_secret(json.loads(s))))
    resolvers_config = ResolversConfig(secrets_resolver, DIDResolverPeerDID())

    # Authcrypt packaging
    loop.run_until_complete(pack_authcrypt(peerdid_sender['peerdid'], resolvers_config,
                                           peerdid_receiver['peerdid'], resolvers_config,
                                           peerdid_mediator['peerdid'], resolvers_config))

if __name__ == "__main__":
    main()
