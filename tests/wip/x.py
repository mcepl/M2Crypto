#!/usr/bin/env python

import os, sys

pid = os.fork()
if pid == 0:
    # child
    os.execlp('openssl', 's_server', '-www')
else:
    # parent
    sys.exit(0)

