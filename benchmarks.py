import asyncio
import sys
import json
import time
import numpy

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

def get_dict_size(d):
    return sys.getsizeof(json.dumps(d))    

async def send(
        iters,
        recipients,
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
    pack_times = []
    unpack_times = []
    sizes = []
    for i in range(iters):
        st_pack = time.process_time()
        pack_result = await pack_encrypted(        
            resolvers_config=resolvers_config_alice,
            message=message,
            frm=ALICE_DID,
            to=BOB_DID,
            pack_config=PackEncryptedConfig(),
        )
        et_pack = time.process_time()
        packed_msg = pack_result.packed_msg
        #    print(f"Sending ${packed_msg} to ${pack_result.service_metadata.service_endpoint}")

        # BOB's MEDIATOR
        forward_bob = await unpack_forward(resolvers_config_mediator1, packed_msg, True)
        #    print(f"Got {forward_bob.forwarded_msg}")
        #    print("Size in bytes: "+str(get_dict_size(forward_bob.forwarded_msg)))
        sizes.append(get_dict_size(forward_bob.forwarded_msg))
        
        # BOB
        st_unpack = time.process_time()
        unpack_result = await unpack(resolvers_config_bob, forward_bob.forwarded_msg)
        et_unpack = time.process_time()
        #    print(f"Got ${unpack_result.message} message")

        pack_times.append(et_pack-st_pack)
        unpack_times.append(et_unpack-st_unpack)

    # print results to stdout
    pack_avg = numpy.average(pack_times)
    pack_std = numpy.std(pack_times)
    unpack_avg = numpy.average(unpack_times)
    unpack_std = numpy.std(unpack_times)
    sizes_avg = numpy.average(sizes)
    sizes_std = numpy.std(sizes)
    
    print("{}\t{}\t{}\t{}\t{}\t{}\t{}"
          .format(recipients,pack_avg,pack_std,unpack_avg,unpack_std,sizes_avg,sizes_std))

def main():

    recipients = int(sys.argv[1])
    iters = int(sys.argv[2])    
    loop = asyncio.get_event_loop()    
    mock_did_resolver = MockDIDResolverWithNonSecrets()
    secrets_resolver_alice = MockSecretsResolverAlice();
    secrets_resolver_bob = MockSecretsResolverBob(recipients);
    secrets_resolver_mediator1 = MockSecretsResolverMediator1();    
    resolvers_config_alice = ResolversConfig(secrets_resolver_alice, mock_did_resolver);
    resolvers_config_bob = ResolversConfig(secrets_resolver_bob, mock_did_resolver);
    resolvers_config_mediator1 = ResolversConfig(secrets_resolver_mediator1, mock_did_resolver);
    loop.run_until_complete(
        send(iters,
             recipients,
             resolvers_config_alice,
             resolvers_config_bob,
             resolvers_config_mediator1)
    )
    return

if __name__ == "__main__":
    main()
