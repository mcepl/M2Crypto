"""
M2Crypto.SSL.TwistedProtocolWrapper

Copyright (c) 2004-2005 Open Source Applications Foundation.
All rights reserved.
"""

RCS_id = '$Id$'

import twisted.protocols.policies as policies
import twisted.internet.reactor
from twisted.protocols.policies import ProtocolWrapper
from twisted.internet.interfaces import ITLSTransport
from zope.interface import implements

import M2Crypto # for M2Crypto.BIO.BIOError
from M2Crypto import m2, X509
from M2Crypto.SSL import Checker

debug = 0


def _alwaysSucceedsPostConnectionCheck(peerX509, expectedHost):
    return 1


def connectSSL(host, port, factory, contextFactory, timeout=30,
               bindAddress=None,
               reactor=twisted.internet.reactor,
               postConnectionCheck=Checker.Checker()):
    """
    A convenience function to start an SSL/TLS connection using Twisted.
    
    See IReactorSSL interface in Twisted. 
    """
    wrappingFactory = policies.WrappingFactory(factory)
    wrappingFactory.protocol = lambda factory, wrappedProtocol: \
        TLSProtocolWrapper(factory,
                           wrappedProtocol,
                           startPassThrough=0,
                           client=1,
                           contextFactory=contextFactory,
                           postConnectionCheck=postConnectionCheck)
    return reactor.connectTCP(host, port, wrappingFactory, timeout, bindAddress)
        

def connectTCP(host, port, factory, timeout=30, bindAddress=None,
               reactor=twisted.internet.reactor,
               postConnectionCheck=Checker.Checker()):
    """
    A convenience function to start a TCP connection using Twisted. 

    NOTE: You must call startTLS(ctx) to go into SSL/TLS mode.

    See IReactorTCP interface in Twisted. 
    """
    wrappingFactory = policies.WrappingFactory(factory)
    wrappingFactory.protocol = lambda factory, wrappedProtocol: \
        TLSProtocolWrapper(factory,
                           wrappedProtocol,
                           startPassThrough=1,
                           client=1,
                           contextFactory=None,
                           postConnectionCheck=postConnectionCheck)
    return reactor.connectTCP(host, port, wrappingFactory, timeout, bindAddress)


def listenSSL(port, factory, contextFactory, backlog=5, interface='',
              reactor=twisted.internet.reactor,  
              postConnectionCheck=_alwaysSucceedsPostConnectionCheck):
    """
    A convenience function to listen for SSL/TLS connections using Twisted. 

    See IReactorSSL interface in Twisted. 
    """
    wrappingFactory = policies.WrappingFactory(factory)
    wrappingFactory.protocol = lambda factory, wrappedProtocol: \
        TLSProtocolWrapper(factory,
                           wrappedProtocol,
                           startPassThrough=0,
                           client=0,
                           contextFactory=contextFactory,
                           postConnectionCheck=postConnectionCheck)
    return reactor.listenTCP(port, wrappingFactory, backlog, interface)


def listenTCP(port, factory, backlog=5, interface='',
              reactor=twisted.internet.reactor,  
              postConnectionCheck=None):
    """
    A convenience function to listen for TCP connections using Twisted. 
    
    NOTE: You must call startTLS(ctx) to go into SSL/TLS mode.

    See IReactorTCP interface in Twisted. 
    """
    wrappingFactory = policies.WrappingFactory(factory)
    wrappingFactory.protocol = lambda factory, wrappedProtocol: \
        TLSProtocolWrapper(factory,
                           wrappedProtocol,
                           startPassThrough=1,
                           client=0,
                           contextFactory=None,
                           postConnectionCheck=postConnectionCheck)
    return reactor.listenTCP(port, wrappingFactory, backlog, interface)


class TLSProtocolWrapper(ProtocolWrapper):
    """
    A SSL/TLS protocol wrapper to be used with Twisted. Typically
    you would not use this class directly. Use connectTCP, 
    connectSSL, listenTCP, listenSSL functions defined above,
    which will hook in this class.
    """

    implements(ITLSTransport)
    
    def __init__(self, factory, wrappedProtocol, startPassThrough, client,
                 contextFactory, postConnectionCheck):
        """
        @param factory:
        @param wrappedProtocol:
        @param startPassThrough:    If true we won't encrypt at all. Need to
                                    call startTLS() later to switch to SSL/TLS.
        @param client:              True if this should be a client protocol.
        @param contextFactory:      Factory that creates SSL.Context objects.
                                    The called function is getContext().
        @param postConnectionCheck: The post connection check callback that
                                    will be called just after connection has
                                    been established but before any real data
                                    has been exchanged. The first argument to
                                    this function is an X509 object, the second
                                    is the expected host name string.
        """
        if debug:
            print 'TwistedProtocolWrapper.__init__'
            
        #ProtocolWrapper.__init__(self, factory, wrappedProtocol)
        #XXX: Twisted 2.0 has a new addition where the wrappingFactory is
        #     set as the factory of the wrappedProtocol. This is an issue
        #     as the wrap should be transparent. What we want is 
        #     the factory of the wrappedProtocol to be the wrappedFactory and
        #     not the outer wrappingFactory. This is how it was implemented in
        #     Twisted 1.3
        self.factory = factory
        self.wrappedProtocol = wrappedProtocol
        
        # wrappedProtocol == client/server instance
        # factory.wrappedFactory == client/server factory

        self.data = '' # Clear text to encrypt and send
        self.encrypted = '' # Encrypted data we need to decrypt and pass on
        self.tlsStarted = 0 # SSL/TLS mode or pass through
        self.checked = 0 # Post connection check done or not
        self.isClient = client
        self.helloDone = 0 # True when hello has been sent
        if postConnectionCheck is None:
            self.postConnectionCheck = _alwaysSucceedsPostConnectionCheck
        else:
            self.postConnectionCheck = postConnectionCheck

        if not startPassThrough:
            self.startTLS(contextFactory.getContext())

    def __del__(self):
        self.clear()

    def clear(self):
        """
        Clear this instance, after which it is ready for reuse.
        """
        if debug:
            print 'TwistedProtocolWrapper.clear'
        if self.tlsStarted:
            m2.bio_free_all(self.sslBio)
            self.sslBio = None
            self.internalBio = None
            self.networkBio = None
        self.data = ''
        self.encrypted = ''
        self.tlsStarted = 0
        self.checked = 0
        self.isClient = 1
        self.helloDone = 0
        # We can reuse self.ctx and it will be deleted automatically
        # when this instance dies
        
    def startTLS(self, ctx):
        """
        Start SSL/TLS. If this is not called, this instance just passes data
        through untouched.
        """
        # NOTE: This method signature must match the startTLS() method Twisted
        #       expects transports to have. This will be called automatically
        #       by Twisted in STARTTLS situations, for example with SMTP.
        if self.tlsStarted:
            raise Exception, 'TLS already started'

        if debug:
            print 'TwistedProtocolWrapper.startTLS'

        self.ctx = ctx

        self.internalBio = m2.bio_new(m2.bio_s_bio())
        m2.bio_set_write_buf_size(self.internalBio, 0)
        self.networkBio = m2.bio_new(m2.bio_s_bio())
        m2.bio_set_write_buf_size(self.networkBio, 0)
        m2.bio_make_bio_pair(self.internalBio, self.networkBio)

        self.sslBio = m2.bio_new(m2.bio_f_ssl())

        self.ssl = m2.ssl_new(self.ctx.ctx)

        if self.isClient:
            m2.ssl_set_connect_state(self.ssl)
        else:
            m2.ssl_set_accept_state(self.ssl)
            
        m2.ssl_set_bio(self.ssl, self.internalBio, self.internalBio)
        m2.bio_set_ssl(self.sslBio, self.ssl, 1)

        # Need this for writes that are larger than BIO pair buffers
        mode = m2.ssl_get_mode(self.ssl)
        m2.ssl_set_mode(self.ssl,
                        mode |
                        m2.SSL_MODE_ENABLE_PARTIAL_WRITE |
                        m2.SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER)

        self.tlsStarted = 1

    def makeConnection(self, transport):
        if debug:
            print 'TwistedProtocolWrapper.makeConnection'
        ProtocolWrapper.makeConnection(self, transport)

    def write(self, data):
        if debug:
            print 'TwistedProtocolWrapper.write'
        if not self.tlsStarted:
            ProtocolWrapper.write(self, data)
            return

        try:
            encryptedData = self._encrypt(data)
            ProtocolWrapper.write(self, encryptedData)
            self.helloDone = 1
        except M2Crypto.BIO.BIOError, e:
            # See http://www.openssl.org/docs/apps/verify.html#DIAGNOSTICS
            # for the error codes returned by SSL_get_verify_result.
            e.args = (m2.ssl_get_verify_result(self.ssl), e.args[0])
            raise e

    def writeSequence(self, data):
        if debug:
            print 'TwistedProtocolWrapper.writeSequence'
        if not self.tlsStarted:
            ProtocolWrapper.writeSequence(self, ''.join(data))
            return

        self.write(''.join(data))

    def loseConnection(self):
        if debug:
            print 'TwistedProtocolWrapper.loseConnection'
        # XXX Do we need to do m2.ssl_shutdown(self.ssl)?
        ProtocolWrapper.loseConnection(self)

    def registerProducer(self, producer, streaming):
        if debug:
            print 'TwistedProtocolWrapper.registerProducer'
        ProtocolWrapper.registerProducer(self, producer, streaming)

    def unregisterProducer(self):
        if debug:
            print 'TwistedProtocolWrapper.unregisterProducer'
        ProtocolWrapper.unregisterProducer(self)

    def stopConsuming(self):
        if debug:
            print 'TwistedProtocolWrapper.stopConsuming'
        ProtocolWrapper.stopConsuming(self)

    def connectionMade(self):
        if debug:
            print 'TwistedProtocolWrapper.connectionMade'
        ProtocolWrapper.connectionMade(self)
        if self.tlsStarted and self.isClient and not self.helloDone:
            self._clientHello()

    def dataReceived(self, data):
        if debug:
            print 'TwistedProtocolWrapper.dataReceived'
        if not self.tlsStarted:
            ProtocolWrapper.dataReceived(self, data)
            return

        self.encrypted += data

        try:
            while 1:
                decryptedData = self._decrypt()

                self._check()

                encryptedData = self._encrypt()
                ProtocolWrapper.write(self, encryptedData)

                ProtocolWrapper.dataReceived(self, decryptedData)

                if decryptedData == '' and encryptedData == '':
                    break
        except M2Crypto.BIO.BIOError, e:
            # See http://www.openssl.org/docs/apps/verify.html#DIAGNOSTICS
            # for the error codes returned by SSL_get_verify_result.
            e.args = (m2.ssl_get_verify_result(self.ssl), e.args[0])
            raise e

    def connectionLost(self, reason):
        if debug:
            print 'TwistedProtocolWrapper.connectionLost'
        self.clear()
        ProtocolWrapper.connectionLost(self, reason)

    def _check(self):
        if debug:
            print 'TwistedProtocolWrapper._check'
        
        if not self.checked and m2.ssl_is_init_finished(self.ssl):
            x = m2.ssl_get_peer_cert(self.ssl)
            if x:
                x509 = X509.X509(x, 1)
            else:
                x509 = None
            if self.isClient:
                host = self.transport.addr[0]
            else:
                host = self.transport.getPeer().host
            if not self.postConnectionCheck(x509, host):
                raise Checker.SSLVerificationError, 'post connection check'
            self.checked = 1

    def _clientHello(self):
        if debug:
            print 'TwistedProtocolWrapper._clientHello'
        
        try:
            # We rely on OpenSSL implicitly starting with client hello
            # when we haven't yet established an SSL connection
            encryptedData = self._encrypt(clientHello=1)
            ProtocolWrapper.write(self, encryptedData)
            self.helloDone = 1
        except M2Crypto.BIO.BIOError, e:
            # See http://www.openssl.org/docs/apps/verify.html#DIAGNOSTICS
            # for the error codes returned by SSL_get_verify_result.
            e.args = (m2.ssl_get_verify_result(self.ssl), e.args[0])
            raise e

    def _encrypt(self, data='', clientHello=0):
        # XXX near mirror image of _decrypt - refactor
        self.data += data
        g = m2.bio_ctrl_get_write_guarantee(self.sslBio)
        if g > 0 and self.data != '' or clientHello:
            r = m2.bio_write(self.sslBio, self.data)
            if r <= 0:
                assert(m2.bio_should_retry(self.sslBio))
            else:
                assert(self.checked)               
                self.data = self.data[r:]
                
        encryptedData = ''
        while 1:
            pending = m2.bio_ctrl_pending(self.networkBio)
            if pending:
                d = m2.bio_read(self.networkBio, pending)
                if d is not None: # This is strange, but d can be None
                    encryptedData += d
                else:
                    assert(m2.bio_should_retry(self.networkBio))
            else:
                break

        return encryptedData

    def _decrypt(self, data=''):
        # XXX near mirror image of _encrypt - refactor
        self.encrypted += data
        g = m2.bio_ctrl_get_write_guarantee(self.networkBio)
        if g > 0 and self.encrypted != '':
            r = m2.bio_write(self.networkBio, self.encrypted)
            if r <= 0:
                assert(m2.bio_should_retry(self.networkBio))
            else:
                self.encrypted = self.encrypted[r:]
                
        decryptedData = ''
        while 1:
            pending = m2.bio_ctrl_pending(self.sslBio)
            if pending:
                d = m2.bio_read(self.sslBio, pending)
                if d is not None: # This is strange, but d can be None
                    decryptedData += d
                else:
                    assert(m2.bio_should_retry(self.sslBio))
            else:
                break

        return decryptedData
