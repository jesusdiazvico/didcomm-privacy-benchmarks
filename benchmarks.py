import asyncio
import sys

from didcomm import (
    Message,
    pack_encrypted,
    PackEncryptedConfig,
    pack_plaintext,
    pack_signed,
    unpack_forward,
    unpack,
)
from didcomm.common.resolvers import ResolversConfig

from mock_secrets_resolver_alice import MockSecretsResolverAlice
from mock_secrets_resolver_bob import MockSecretsResolverBob
from mock_secrets_resolver_mediator1 import MockSecretsResolverMediator1
from mock_did_resolver import MockDIDResolverWithNonSecrets
from common import ( ALICE_DID, BOB_DID )

async def send(
        resolvers_config_alice,
        resolvers_config_bob,
        resolvers_config_mediator1
):
    # ALICE
    message = Message(
        body={"aaa": 1, "bbb": 2},
        id="1234567890",
        type="my-protocol/1.0",
        frm=ALICE_DID,
        to=[BOB_DID],
    )

    #    pack_result = await pack_encrypted(
    pack_result = await pack_encrypted(        
        resolvers_config=resolvers_config_alice,
        message=message,
        frm=ALICE_DID,
        to=BOB_DID,
        pack_config=PackEncryptedConfig(),
    )
    packed_msg = pack_result.packed_msg

    print("\nMESSAGE BEING SENT BY ALICE")
    print(f"Sending ${packed_msg} to ${pack_result.service_metadata.service_endpoint}")
    print("Size in bytes: "+str(sys.getsizeof(packed_msg)))

    # BOB's MEDIATOR
    forward_bob = await unpack_forward(resolvers_config_mediator1, packed_msg, True)
    print("\nPAYLOAD AFTER MEDIATOR DECRYPTION")
    print(f"Got {forward_bob.forwarded_msg}")
    print("Size in bytes: "+str(sys.getsizeof(forward_bob.forwarded_msg)))

    # BOB    
    unpack_result = await unpack(resolvers_config_bob, forward_bob.forwarded_msg)
    print("\nPAYLOAD AFTER BOB DECRYPTION")
    print(f"Got ${unpack_result.message} message")


def main():

    loop = asyncio.get_event_loop()
    
    mock_did_resolver = MockDIDResolverWithNonSecrets()
    secrets_resolver_alice = MockSecretsResolverAlice();
    secrets_resolver_bob = MockSecretsResolverBob();
    secrets_resolver_mediator1 = MockSecretsResolverMediator1();    
    resolvers_config_alice = ResolversConfig(secrets_resolver_alice, mock_did_resolver);
    resolvers_config_bob = ResolversConfig(secrets_resolver_bob, mock_did_resolver);
    resolvers_config_mediator1 = ResolversConfig(secrets_resolver_mediator1, mock_did_resolver);
    loop.run_until_complete(send(resolvers_config_alice,
                                 resolvers_config_bob,
                                 resolvers_config_mediator1))
    return

if __name__ == "__main__":
    main()
