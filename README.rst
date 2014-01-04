======
HREPSH
======


Security
========

Key Derivation
--------------
HREPSH stores a system-wide secret in ``/etc/hrepsh``, which should only be
readable by root. Using this secret, a unique, per-user and per-application
key is derived as follows::

        key(secret, user, path) = HMAC(user, HMAC(path, secret))
