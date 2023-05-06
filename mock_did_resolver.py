from didcomm import DIDResolverInMemory, DIDDoc
from did_doc_alice import (
    DID_DOC_ALICE_WITH_NO_SECRETS,
    DID_DOC_ALICE_SPEC_TEST_VECTORS
)
from did_doc_bob import (
    DID_DOC_BOB_WITH_NO_SECRETS,
    DID_DOC_BOB_SPEC_TEST_VECTORS
)
from common import BOB_DID

from did_doc_mediator1 import DID_DOC_MEDIATOR1

class MockDIDResolverAllInSecrets(DIDResolverInMemory):
    def __init__(self,nkaBob):
        if nkaBob < 1 or nkaBob > 4: return
        ka = DID_DOC_BOB_SPEC_TEST_VECTORS.key_agreement[0:nkaBob]
        vm = DID_DOC_BOB_SPEC_TEST_VECTORS.verification_method[0:nkaBob]
        DID_DOC_BOB = DIDDoc(
            id=BOB_DID,
            authentication=[],
            key_agreement=ka,
            service=[],
            verification_method=vm
            )
        DID_DOC_BOB_NS = DIDDoc(
            id=BOB_DID,
            authentication=[],
            key_agreement=ka,
            service=DID_DOC_BOB_WITH_NO_SECRETS.service,
            verification_method=vm
        )
        super().__init__(
            did_docs=[
                DID_DOC_ALICE_SPEC_TEST_VECTORS,
                DID_DOC_BOB, #DID_DOC_BOB_SPEC_TEST_VECTORS,
#                DID_DOC_CHARLIE,
                DID_DOC_MEDIATOR1,
#                DID_DOC_MEDIATOR2,
            ]
        )


class MockDIDResolverWithNonSecrets(DIDResolverInMemory):
    def __init__(self,nkaBob):
        if nkaBob < 1 or nkaBob > 4: return
        ka = DID_DOC_BOB_SPEC_TEST_VECTORS.key_agreement[0:nkaBob]
        vm = DID_DOC_BOB_SPEC_TEST_VECTORS.verification_method[0:nkaBob]
        DID_DOC_BOB = DIDDoc(
            id=BOB_DID,
            authentication=[],
            key_agreement=ka,
            service=[],
            verification_method=vm
            )
        DID_DOC_BOB_NS = DIDDoc(
            id=BOB_DID,
            authentication=[],
            key_agreement=ka,
            service=DID_DOC_BOB_WITH_NO_SECRETS.service,
            verification_method=vm
        )        
        super().__init__(
            did_docs=[
                DID_DOC_ALICE_WITH_NO_SECRETS,
                DID_DOC_BOB_NS,#DID_DOC_BOB_WITH_NO_SECRETS,
 #               DID_DOC_CHARLIE,
                DID_DOC_MEDIATOR1,
#                DID_DOC_MEDIATOR2,
            ]
        )
