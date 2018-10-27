# Copyright 2018 Travis Ralston
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

__version__ = "0.0.1"


from twisted.internet import defer, threads

import logging
import hvac
import os
import hashlib
import hmac


logger = logging.getLogger("synapse_vault_auth_provider")


class VaultAuthProvider(object):
    def __init__(self, config, account_handler):
        self.account_handler = account_handler

        if not hvac:
            raise RuntimeError('Missing hvac library')

        self.vault_path_root = config.vault_path_root

        token = config.vault_token or os.environ["VAULT_TOKEN"]
        self.client = hvac.Client(url=config.vault_url, token=token)

    def get_supported_login_types(self):
        return {
            "io.t2bot.vault": ("token_hash",),
        }

    @defer.inlineCallbacks
    def check_auth(self, username, login_type, login_dict):
        if login_type != "io.t2bot.vault":
            raise RuntimeError("Unsupported login type")

        if not login_dict or not login_dict["token_hash"]:
            logger.warning("Missing token hash in login request")
            defer.returnValue(False)

        user_id = self.account_handler.get_qualified_user_id(username)

        if not (yield self.account_handler.check_user_exists(user_id)):
            logger.warning("User does not exist")
            defer.returnValue(False)

        # Read the expected token from Vault and compare hmacs
        secret = self.client.read(self.vault_path_root + '/' + user_id)
        calculated = hmac.new(secret, user_id, hashlib.sha256).hexdigest()

        if not hmac.compare_digest(calculated, login_dict["token_hash"]):
            logger.warning("Mismatch hashes")
            defer.returnValue(False)

        # All is well in the world
        defer.returnValue(True)
