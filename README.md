# Cert Warden Client

Centralized Certificate Management
Conveniently Leverage Let's Encrypt to Secure Your Infrastructure

> This fork adds support for Cloudflare Zero Trust authentication using the environment variables `CW_CLIENT_CF_ACCESS_CLIENT_ID` and `CW_CLIENT_CF_ACCESS_CLIENT_SECRET`.

## More Information

https://www.certwarden.com/

## Client

Cert Warden Client is a lightweight client that automatically fetches
certificates from Cert Warden and runs an http server to receive
further updates directly from the Cert Warden Server.

Cert Warden Client is also able to restart docker containers to make
them pick up new certificate files, when they're written.
