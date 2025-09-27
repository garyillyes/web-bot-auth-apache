# Apache Web Bot Auth Module (demo) (web-bot-auth-apache)

This is a sample Apache module that provides a framework for implementing the
web-bot-auth specification. It extracts the necessary headers and provides
hooks where you can add your signature verification logic.

## Compilation and Installation

To compile and install this module, you'll need to have the Apache apxs tool
installed. This is usually included in the apache2-dev or httpd-devel package,
depending on your Linux distribution.

### Compile and load the module:

`apxs -c -i mod_web_bot_auth.c -lcurl -lssl -lcrypto`

This command will compile the C source file into a dynamically shared object
(.so) and install it into your Apache modules directory.

#### Configure Apache:

You need to tell Apache to load the module. Create a new file in your Apache
configuration directory (e.g., /etc/apache2/mods-available/web_bot_auth.load)
with the following content:
`LoadModule web_bot_auth_module /usr/lib/apache2/modules/mod_web_bot_auth.so`

The path to the module might be different on your system.

#### Enable the module:

You can enable the module using the a2enmod command:
`a2enmod web_bot_auth`

#### Configure a location to use the handler:

In your site's configuration file
(e.g., /etc/apache2/sites-available/000-default.conf), add a <Location> block
to specify where the module should be active:

```
<Location />
    SetHandler web-bot-auth
</Location>
```

Restart Apache:
`systemctl restart apache2`

## How it Works

This module registers a handler that runs for every request. It checks for the
Signature, Signature-Input, and Signature-Agent headers. If they are present,
it attempts to verify the signature. Relies on:

- libcurl: For making HTTP requests to fetch the public key from the
  Signature-Agent URL.
- OpenSSL: For performing the cryptographic operations needed to verify the
  signature.
