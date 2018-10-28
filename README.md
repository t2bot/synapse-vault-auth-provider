# synapse-vault-auth-provider

Synapse auth provider to enable [vault-plugin-secrets-matrix](https://github.com/t2bot/vault-plugin-secrets-matrix)

# Install / Upgrade

In the same python used by synapse, `pip install https://github.com/t2bot/synapse-vault-auth-provider/tarball/master`

# Usage

Add the following to your `homeserver.yaml`:

```yaml
password_providers:
  - module: "synapse-vault-auth-provider.VaultAuthProvider"
    config:
      # The address where this module can reach Vault
      vault_url: https://localhost:8200

      # The Vault token to use. Should have read only access to the vault_path_root
      # described below. Comment out to use the VAULT_TOKEN environment variable.
      vault_token: "YourTokenHere"

      # The base path this provider will use to look for user shared secrets. Secrets
      # are stored in Vault to verify that the requesting party has the appropriate
      # permissions to actually obtain an access_token for a user.
      #
      # For example, if an access token for the user @alice:example.org was requested,
      # this provider will get the shared secret from "secret/matrix/users/@alice:example.org"
      # and use that secret to verify the request. Therefore, the Vault token listed
      # above should have read access to secret/matrix/users/* (or whatever your path
      # actually is).
      #
      # Note that this is the path itself without the mount point. In the examples above,
      # this would end up being "matrix/users" while the mount point is "secret"
      vault_path_root: "matrix/users"

      # The mount point for the above path root.
      vault_kv_mount_point: "secret"
```

Synapse will need to be restarted to pick up the configuration change.

## Logging

All logging is done under the name `synapse_vault_auth_provider` and should show up
in your homeserver's logs during an applicable login request. If the logging doesn't
show up, change your logging configuration to include:

```yaml
loggers:
  synapse_vault_auth_provider:
    level: INFO
```

Synapse will need to be restarted to pick up logging configuration changes.

# Example Login

First, the client should request the login flows to ensure the provider is active
and able to be used:

```
GET /_matrix/client/r0/login

Response:
{
  "flows": [
    {
      "type": "io.t2bot.vault"
    }
  ]
}
```

Assuming the `type` above is listed as a login flow, the client should then get the
shared secret for the user it wishes to get an access token for. The shared secret,
if using the default config, would be mounted at `secret/matrix/users/@someone:example.org`
by an external party (not done by this provider).

The client then takes a sha256 hmac of the shared secret and user ID, providing that
as `token_hash` in a login request:

```
POST /_matrix/client/r0/login

Body:
{
  "type": "io.t2bot.vault",
  "identifier": {
    "type": "m.id.user",
    "user": "@someone:example.org"
  },
  "token_hash": "some_very_long_sha256_string"
}

Response:
{
  "user_id": "@someone:example.org",
  "access_token": "SomeSortOfAccessToken",
  "device_id": "SomeDevice"
}
```

Assuming the hash matches what the provider expects, the response above will be returned
for the client to use.

# Shared secret storage in Vault

If you haven't already, enable the `kv` plugin:

```
vault kv enable-versioning secret/
```

Configure your permissions and tokens to have applicable read/write access to `secret/matrix/users/*`,
then write your secret:

```
vault kv put secret/matrix/users/@alice:example.org login_secret=YourRandomString
```

And there you go! The provider will use the value of `login_secret` as the shared secret
for that user.
