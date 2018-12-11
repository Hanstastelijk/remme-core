# Copyright 2018 REMME
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ------------------------------------------------------------------------

import logging
import binascii
import hashlib
import abc

import ed25519
import ecdsa

from datetime import datetime, timedelta

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from sawtooth_sdk.processor.exceptions import InvalidTransaction


from remme.settings import SETTINGS_STORAGE_PUB_KEY
from remme.tp.basic import (
    BasicHandler, get_data, get_multiple_data, PB_CLASS, PROCESSOR,
)
from remme.tp.account import AccountHandler

from remme.protos.account_pb2 import Account
from remme.protos.pub_key_pb2 import (
    PubKeyStorage,
    NewPubKeyPayload, RevokePubKeyPayload, PubKeyMethod
)
from remme.settings.helper import _get_setting_value

LOGGER = logging.getLogger(__name__)

FAMILY_NAME = 'pub_key'
FAMILY_VERSIONS = ['0.1']

PUB_KEY_ORGANIZATION = 'REMME'
PUB_KEY_MAX_VALIDITY = timedelta(365)
PUB_KEY_STORE_PRICE = 10


def detect_processor_cls(config):
    if isinstance(config, NewPubKeyPayload.RSAConfiguration):
        return RSAProcessor
    elif isinstance(config, NewPubKeyPayload.ECDSAConfiguration):
        return ECDSAProcessor
    elif isinstance(config, NewPubKeyPayload.Ed25519Configuration):
        return Ed25519Processor
    raise NotImplementedError


class BasePubKeyProcessor(metaclass=abc.ABCMeta):

    def __init__(self, entity_hash, entity_hash_signature,
                 valid_from, valid_to, hashing_algorithm, config):
        self._entity_hash = entity_hash
        self._entity_hash_signature = entity_hash_signature
        self._valid_from = valid_from
        self._valid_to = valid_to
        self._hashing_algorithm = hashing_algorithm
        self._config = config

    @abc.abstractmethod
    def get_hashing_algorithm(self):
        """Return libriary special algoritm in according to protobuf
        """

    @abc.abstractmethod
    def get_public_key(self):
        """Get public key from given signature or points
        """

    @abc.abstractmethod
    def verify(self):
        """Verify if signature was successfull
        """


class RSAProcessor(BasePubKeyProcessor):

    def verify(self):
        verifier = load_pem_public_key(self.config.key,
                                       default_backend())

        try:
            verifier.verify(self._entity_hash_signature, self._entity_hash,
                            self.get_padding(), self.get_hashing_algorithm()())
            return True
        except InvalidSignature:
            return False

    def get_public_key(self):
        return binascii.hexlify(self.config.key)

    def get_hashing_algorithm(self):
        alg_name = NewPubKeyPayload.HashingAlgorithm \
            .Name(self.hashing_algorithm)
        return getattr(hashes, alg_name)

    def get_padding(self):
        if self._config.padding == NewPubKeyPayload.PSS:
            return padding.PSS(mgf=padding.MGF1(self.get_hashing_algorithm()()),
                               salt_length=padding.PSS.MAX_LENGTH)
        elif self._config.padding == NewPubKeyPayload.PKCS1v15:
            return padding.PKCS1v15()
        else:
            raise NotImplementedError('Unsupported RSA padding')


class ECDSAProcessor(BasePubKeyProcessor):

    def verify(self):
        verifier = ecdsa.VerifyingKey.from_string(self.get_public_key(),
                                                  self.get_curve_type())
        try:
            verifier.verify(self._entity_hash_signature, self._entity_hash,
                            self.get_hashing_algorithm())
            return True
        except ecdsa.BadSignatureError:
            return False

    def get_public_key(self):
        return binascii.hexlify(self.config.key)

    def get_hashing_algorithm(self):
        alg_name = NewPubKeyPayload.HashingAlgorithm \
            .Name(self.hashing_algorithm).lower()
        return getattr(hashlib, alg_name)

    def get_curve_type(self):
        curve_name = NewPubKeyPayload.ECDSAConfiguration.EC \
            .Name(self.config.ec)
        return getattr(ecdsa, curve_name)


class Ed25519Processor(BasePubKeyProcessor):

    def verify(self):
        verifier = ed25519.VerifyingKey(self.get_public_key(), encoding="hex")
        try:
            verifier.verify(self._entity_hash_signature,
                            self._entity_hash,
                            encoding="hex")
            return True
        except ed25519.BadSignatureError:
            return False

    def get_public_key(self):
        return binascii.hexlify(self.config.key)

    def get_hashing_algorithm(self):
        raise NotImplementedError


class PubKeyHandler(BasicHandler):
    def __init__(self):
        super().__init__(FAMILY_NAME, FAMILY_VERSIONS)

    def get_state_processor(self):
        return {
            PubKeyMethod.STORE: {
                PB_CLASS: NewPubKeyPayload,
                PROCESSOR: self._store_pub_key
            },
            PubKeyMethod.REVOKE: {
                PB_CLASS: RevokePubKeyPayload,
                PROCESSOR: self._revoke_pub_key
            }
        }

    def _store_pub_key(self, context, signer_pubkey, transaction_payload):
        conf_name = transaction_payload.WhichOneof('configuration')
        if not conf_name:
            raise InvalidTransaction('Configuration for public key not set')

        conf_payload = getattr(transaction_payload, conf_name)

        processor_cls = detect_processor_cls(conf_payload)
        processor = processor_cls(transaction_payload.entity_hash,
                                  transaction_payload.entity_hash_signature,
                                  transaction_payload.valid_from,
                                  transaction_payload.valid_to,
                                  transaction_payload.hashing_algorithm,
                                  conf_payload)

        public_key = processor.get_public_key()

        address = self.make_address_from_data(public_key)
        LOGGER.info('Pub key address {}'.format(address))

        account_address = AccountHandler() \
            .make_address_from_data(signer_pubkey)
        LOGGER.info('Account address {}'.format(address))
        data, account = get_multiple_data(context, [
            (address, PubKeyStorage), (account_address, Account)
        ])
        if data:
            raise InvalidTransaction('This pub key is already registered.')

        sig_is_valid = processor.validate()
        if sig_is_valid is False:
            raise InvalidTransaction('Invalid signature')

        valid_from = datetime.fromtimestamp(processor.valid_from)
        valid_to = datetime.fromtimestamp(processor.valid_to)

        if valid_to - valid_from > PUB_KEY_MAX_VALIDITY:
            raise InvalidTransaction('The public key validity exceeds '
                                     'the maximum value.')

        data = PubKeyStorage()
        data.owner = signer_pubkey
        data.payload.CopyFrom(transaction_payload)
        data.is_revoked = False

        if not account:
            account = Account()

        state = {account_address: account, address: data}
        is_economy_enabled = _get_setting_value(context,
                                                'remme.economy_enabled',
                                                'true').lower()
        if is_economy_enabled == 'true':
            storage_pub_key = _get_setting_value(context,
                                                 SETTINGS_STORAGE_PUB_KEY)
            if not storage_pub_key:
                raise InvalidTransaction('The storage public key not set.')

            storage_address = AccountHandler() \
                .make_address_from_data(storage_pub_key)

            if storage_address != account_address:
                transfer_state = AccountHandler() \
                    .create_transfer(context, account_address, storage_address,
                                     PUB_KEY_STORE_PRICE)
                state.update(transfer_state)
                # update account from transfer state
                account = transfer_state[account_address]

        if address not in account.pub_keys:
            account.pub_keys.append(address)

        return state

    def _revoke_pub_key(self, context, signer_pubkey, transaction_payload):
        data = get_data(context, PubKeyStorage, transaction_payload.address)
        if data is None:
            raise InvalidTransaction('No such pub key.')
        if signer_pubkey != data.owner:
            raise InvalidTransaction('Only owner can revoke the pub key.')
        if data.is_revoked:
            raise InvalidTransaction('The pub key is already revoked.')
        data.is_revoked = True

        LOGGER.info('Revoked the pub key on address {}'.format(transaction_payload.address))

        return {transaction_payload.address: data}
