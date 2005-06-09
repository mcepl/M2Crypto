"""
M2Crypto.SSL.Checker

Copyright (c) 2004-2005 Open Source Applications Foundation.
All rights reserved.
"""

RCS_id='$Id$'

from M2Crypto import util, EVP
import re

class SSLVerificationError(Exception):
    pass

class NoCertificate(SSLVerificationError):
    pass

class WrongCertificate(SSLVerificationError):
    pass

class WrongHost(SSLVerificationError):
    pass

class Checker:
    def __init__(self, host=None, peerCertHash=None, peerCertDigest='sha1'):
        self.host = host
        self.fingerprint = peerCertHash
        self.digest = peerCertDigest
        self.numericIpMatch = re.compile('^[0-9]+(\.[0-9]+)*$')

    def __call__(self, peerCert, host=None):
        if peerCert is None:
            raise NoCertificate, 'peer did not return certificate'

        if host is not None:
            self.host = host
        
        if self.fingerprint:
            if self.digest not in ('sha1', 'md5'):
                raise ValueError, 'unsupported digest "%s"' %(self.digest)

            if (self.digest == 'sha1' and len(self.fingerprint) != 40) or \
               (self.digest == 'md5' and len(self.fingerprint) != 32):
                raise WrongCertificate, 'peer certificate fingerprint length does not match'
            
            der = peerCert.as_der()
            md = EVP.MessageDigest(self.digest)
            md.update(der)
            digest = md.final()
            if util.octx_to_num(digest) != int(self.fingerprint, 16):
                raise WrongCertificate, 'peer certificate fingerprint does not match'

        if self.host:
            hostValidationPassed = False

            # XXX subjectAltName might contain multiple fields
            # subjectAltName=DNS:somehost
            try:
                subjectAltName = peerCert.get_ext('subjectAltName').get_value()
                if not self._match(self.host, subjectAltName, True):
                    raise WrongHost, 'subjectAltName does not match host. Expected "DNS:%s", got "%s".' %(self.host, subjectAltName)
                hostValidationPassed = True
            except LookupError:
                pass

            # commonName=somehost
            if not hostValidationPassed:
                try:
                    commonName = peerCert.get_subject().CN
                    if not self._match(self.host, commonName):
                        raise WrongHost, 'peer certificate commonName does not match host. Expected "%s", got "%s".' %(self.host, commonName)
                except AttributeError:
                    raise WrongHost, 'no commonName in peer certificate'

        return True

    def _match(self, host, certHost, subjectAltName=False):
        """
        >>> check = Checker()
        >>> check._match(host='my.example.com', certHost='DNS:my.example.com', subjectAltName=True)
        True
        >>> check._match(host='my.example.com', certHost='DNS:*.example.com', subjectAltName=True)
        True
        >>> check._match(host='my.example.com', certHost='DNS:m*.example.com', subjectAltName=True)
        True
        >>> check._match(host='my.example.com', certHost='DNS:m*ample.com', subjectAltName=True)
        False
        >>> check._match(host='my.example.com', certHost='my.example.com')
        True
        >>> check._match(host='my.example.com', certHost='*.example.com')
        True
        >>> check._match(host='my.example.com', certHost='m*.example.com')
        True
        >>> check._match(host='my.example.com', certHost='m*.EXAMPLE.com')
        True
        >>> check._match(host='my.example.com', certHost='m*ample.com')
        False
        >>> check._match(host='my.example.com', certHost='*.*.com')
        False
        >>> check._match(host='1.2.3.4', certHost='1.2.3.4')
        True
        >>> check._match(host='1.2.3.4', certHost='*.2.3.4')
        False
        >>> check._match(host='1234', certHost='1234')
        True
        """
        # XXX See RFC 2818 and 3280 for matching rules, this is not
        # XXX yet complete.

        host = host.lower()
        certHost = certHost.lower()

        if subjectAltName:
            if certHost[:4] != 'dns:':
                return False
            certHost = certHost[4:]
        
        if host == certHost:
            return True

        if certHost.count('*') > 1:
            # Not sure about this, but being conservative
            return False

        if self.numericIpMatch.match(host) or \
               self.numericIpMatch.match(certHost.replace('*', '')):
            # Not sure if * allowed in numeric IP, but think not.
            return False

        if certHost.find('\\') > -1:
            # Not sure about this, maybe some encoding might have these.
            # But being conservative for now, because regex below relies
            # on this.
            return False

        # Massage certHost so that it can be used in regex
        certHost = certHost.replace('.', '\.')
        certHost = certHost.replace('*', '[^\.]*')
        if re.compile('^%s$' %(certHost)).match(host):
            return True

        return False


if __name__ == '__main__':
    import doctest
    doctest.testmod()
