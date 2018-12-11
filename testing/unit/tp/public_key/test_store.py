"""
Provide tests for public key handler apply method implementation.
"""
import binascii
import datetime
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sawtooth_sdk.processor.exceptions import InvalidTransaction
from sawtooth_sdk.protobuf.processor_pb2 import TpProcessRequest
from sawtooth_sdk.protobuf.setting_pb2 import Setting
from sawtooth_sdk.protobuf.transaction_pb2 import (
    Transaction,
    TransactionHeader,
)

from remme.protos.account_pb2 import (
    Account,
    AccountMethod,
    TransferPayload,
)
from remme.protos.pub_key_pb2 import (
    PubKeyStorage,
    NewPubKeyPayload,
    PubKeyMethod,
)
from remme.protos.transaction_pb2 import TransactionPayload
from remme.shared.utils import hash512
from remme.settings.helper import _make_settings_key
from remme.settings import SETTINGS_STORAGE_PUB_KEY
from remme.tp.pub_key import (
    PUB_KEY_MAX_VALIDITY,
    PUB_KEY_STORE_PRICE,
    PubKeyHandler,
)
from testing.conftest import create_signer
from testing.utils.client import (
    generate_address,
    generate_entity_hash,
    generate_message,
    generate_settings_address,
    generate_signature,
)
from testing.mocks.stub import StubContext

SENDER_PRIVATE_KEY = '1cb15ecfe1b3dc02df0003ac396037f85b98cf9f99b0beae000dc5e9e8b6dab4'
SENDER_PUBLIC_KEY = '03ecc5cb4094eb05319be6c7a63ebf17133d4ffaea48cdcfd1d5fc79dac7db7b6b'
SENDER_ADDRESS = '112007b9433e1da5c624ff926477141abedfd57585a36590b0a8edc4104ef28093ee30'
SENDER_INITIAL_BALANCE = 5000

STORAGE_PUBLIC_KEY = generate_settings_address('remme.settings.storage_pub_key')
STORAGE_ADDRESS = generate_address('account', STORAGE_PUBLIC_KEY)
STORAGE_SETTING_ADDRESS = _make_settings_key('remme.settings.storage_pub_key')

IS_NODE_ECONOMY_ENABLED_ADDRESS = generate_settings_address('remme.economy_enabled')

RANDOM_ALREADY_STORED_SENDER_PUBLIC_KEY = 'a23be17ca9c3bd150627ac6469f11ccf25c0c96d8bb8ac333879d3ea06a90413cd4536'
RANDOM_NODE_PUBLIC_KEY = '039d6881f0a71d05659e1f40b443684b93c7b7c504ea23ea8949ef5216a2236940'

CURRENT_TIMESTAMP = datetime.datetime.now().timestamp()
CURRENT_TIMESTAMP_PLUS_YEAR = CURRENT_TIMESTAMP + PUB_KEY_MAX_VALIDITY.total_seconds()

RSA_PUBLIC_KEY_TO_STORE_TYPE_VALUE = PERSONAL_PUBLIC_KEY_TYPE_VALUE = 0

TRANSACTION_REQUEST_ACCOUNT_HANDLER_PARAMS = {
    'family_name': PubKeyHandler().family_name,
    'family_version': PubKeyHandler()._family_versions[0],
}

def test_public_key_handler_apply():
    """
    Case: send transaction request, to store RSA public key to blockchain, to the public handler.
    Expect: public key information is stored to blockchain linked to owner address. Owner paid tokens for storing.
    """
    private_key_from_public_key_to_store = private_key_object = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend(),
    )

    public_key_to_store = private_key_object.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    address_from_public_key_to_store = generate_address('pub_key', public_key_to_store)

    message = generate_message('some-data-for-storing')
    entity_hash = generate_entity_hash(message)
    entity_hash_signature = generate_signature(entity_hash, private_key_from_public_key_to_store)

    inputs = outputs = [
        address_from_public_key_to_store,
        SENDER_ADDRESS,
        STORAGE_PUBLIC_KEY,
        STORAGE_ADDRESS,
        IS_NODE_ECONOMY_ENABLED_ADDRESS,
    ]

    new_public_key_payload = NewPubKeyPayload(
        public_key=public_key_to_store,
        public_key_type=RSA_PUBLIC_KEY_TO_STORE_TYPE_VALUE,
        entity_type=PERSONAL_PUBLIC_KEY_TYPE_VALUE,
        entity_hash=binascii.hexlify(entity_hash),
        entity_hash_signature=entity_hash_signature,
        valid_from=int(CURRENT_TIMESTAMP),
        valid_to=int(CURRENT_TIMESTAMP_PLUS_YEAR),
    )

    transaction_payload = TransactionPayload()
    transaction_payload.method = PubKeyMethod.STORE
    transaction_payload.data = new_public_key_payload.SerializeToString()

    serialized_transaction_payload = transaction_payload.SerializeToString()

    transaction_header = TransactionHeader(
        signer_public_key=SENDER_PUBLIC_KEY,
        family_name=TRANSACTION_REQUEST_ACCOUNT_HANDLER_PARAMS.get('family_name'),
        family_version=TRANSACTION_REQUEST_ACCOUNT_HANDLER_PARAMS.get('family_version'),
        inputs=inputs,
        outputs=outputs,
        dependencies=[],
        payload_sha512=hash512(data=serialized_transaction_payload),
        batcher_public_key=RANDOM_NODE_PUBLIC_KEY,
        nonce=time.time().hex().encode(),
    )

    serialized_header = transaction_header.SerializeToString()

    transaction_request = TpProcessRequest(
        header=transaction_header,
        payload=serialized_transaction_payload,
        signature=create_signer(private_key=SENDER_PRIVATE_KEY).sign(serialized_header),
    )

    sender_account = Account()
    sender_account.balance = SENDER_INITIAL_BALANCE
    sender_account.pub_keys.append(RANDOM_ALREADY_STORED_SENDER_PUBLIC_KEY)
    serialized_sender_account = sender_account.SerializeToString()

    storage_account = Account()
    storage_account.balance = 0
    serialized_storage_account = storage_account.SerializeToString()

    storage_setting = Setting()
    storage_setting.entries.add(key=SETTINGS_STORAGE_PUB_KEY, value=STORAGE_PUBLIC_KEY)
    serialized_storage_setting = storage_setting.SerializeToString()

    mock_context = StubContext(inputs=inputs, outputs=outputs, initial_state={
        SENDER_ADDRESS: serialized_sender_account,
        STORAGE_SETTING_ADDRESS: serialized_storage_setting,
        STORAGE_ADDRESS: serialized_storage_account,
    })

    expected_public_key_storage = PubKeyStorage()
    expected_public_key_storage.owner = SENDER_PUBLIC_KEY
    expected_public_key_storage.payload.CopyFrom(new_public_key_payload)
    expected_public_key_storage.revoked = False
    expected_serialized_public_key_storage = expected_public_key_storage.SerializeToString()

    expected_sender_account = Account()
    expected_sender_account.balance = SENDER_INITIAL_BALANCE - PUB_KEY_STORE_PRICE
    expected_sender_account.pub_keys.append(RANDOM_ALREADY_STORED_SENDER_PUBLIC_KEY)
    expected_sender_account.pub_keys.append(address_from_public_key_to_store)
    expected_serialized_sender_account = expected_sender_account.SerializeToString()

    expected_storage_account = Account()
    expected_storage_account.balance = 0 + PUB_KEY_STORE_PRICE
    expected_serialized_storage_account = expected_storage_account.SerializeToString()

    expected_state = {
        SENDER_ADDRESS: expected_serialized_sender_account,
        address_from_public_key_to_store: expected_serialized_public_key_storage,
        STORAGE_ADDRESS: expected_serialized_storage_account,
    }

    PubKeyHandler().apply(transaction=transaction_request, context=mock_context)

    state_as_list = mock_context.get_state(addresses=[
        SENDER_ADDRESS, address_from_public_key_to_store, STORAGE_ADDRESS,
    ])

    state_as_dict = {entry.address: entry.data for entry in state_as_list}

    assert expected_state == state_as_dict
