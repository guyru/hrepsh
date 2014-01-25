======
HREPSH
======

Installation
============

Seeding the secret file::

  # touch /etc/hrepsh
  # chmod 0200 /etc/hrepsh
  # dd ibs=1 count=32 if=/dev/random of=/etc/hrepsh
  # chmod 0400 /etc/hrepsh

Dependencies
------------
In order to compile hrepsh you will need:

* Crypto++
* Boost

Security
========

Key Derivation
--------------
HREPSH stores a system-wide secret in ``/etc/hrepsh``, which should only be
readable by root. Using this secret, a unique, per-user and per-application
key is derived as follows::

        key(secret, user, path) = HMAC(secret, user + "\0" + path)
