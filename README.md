sshpass-keyring
=======

If you need to login to a server that, for whatever reason, has public key auth disabled, you can use this script
to automate login via username and password.

Your password will be stored in the appropriate keyring backend. (e.g. Keychain on Mac OS X)

add ssh login use google auth code，save code in keyring.

可以添加到 .oh-my-zsh plugin 

Requires:

* Python
* pip (or easy_install)
* pip install pexpect
* pip install keyring


## reference

[python sshpass](https://github.com/bdelliott/sshpass)

