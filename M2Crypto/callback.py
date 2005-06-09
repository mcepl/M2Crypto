"""Copyright (c) 1999-2003 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id$'

import SSL

def genparam_callback(p, n):
    from sys import stdout
    ch=['.','+','*','\n']
    stdout.write(ch[p])
    stdout.flush()

def passphrase_callback(v, prompt1='Enter passphrase:', prompt2='Verify passphrase:'):
    from getpass import getpass
    while 1:
        try:
            p1=getpass(prompt1)
            if v:
                p2=getpass(prompt2)
                if p1==p2:
                    break
            else:
                break
        except KeyboardInterrupt:
            return None
    return p1


class Callback:
    def __init__(self, id):
        self.id = id
        self.generator = genparam_callback
        self.passphrase = passphrase_callback
        self.ssl_verify = SSL.ssl_verify_callback
        self.ssl_info = SSL.ssl_info_callback
        # TODO
        self.bio_info = None


# Following is cribbed from Zope's lib/python/ZODB/Transaction.py. Thanks DC!
try:
    import thread
    _cb = {}
    def get_callback(_id=thread.get_ident, _cb=_cb):
        id = _id()
        try:
            cb = _cb[id]
        except KeyError:
            _cb[id] = cb = Callback(id)
        return cb
    del thread

except:
    _cb = Callback(None)
    def get_callback(_cb=_cb):
        return _cb

del _cb

