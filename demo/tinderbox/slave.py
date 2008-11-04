#!/usr/bin/env python
#
# This is a sample Tinderbox2 buildslave script
#

# XXX read from an ini file
BUILD_NAME = 'example-linux'
TO_EMAIL = 'builds@example.com'
FROM_EMAIL = 'myemail@example.com'
SMTP_USER = 'myemail'
SMTP_PASSWORD = 'secret'
SMTP_SERVER = 'smtp.example.com'
SMTP_PORT = 587

import time, smtplib, os
import build_lib as bl

# These commands assume we are running on a unix-like system where default
# build options work and all prerequisites are installed and in PATH etc.
commands = [
  ['uname', '-a'],
  ['swig', '-version'],
  ['openssl', 'version'],
  ['python', '--version'],
  ['svn', 'co', 'http://svn.osafoundation.org/m2crypto/trunk', 'm2crypto'],
  ['python', 'setup.py', 'clean', '--all', 'build'],
  ['python', 'setup.py', 'test']
]

status = 'success'

cwd = os.getcwd()

bl.initLog(None)

starttime = int(time.time())

for command in commands:
    if bl.runCommand(command, timeout=120):
        if command[-1] == 'test': # XXX
            status = 'test_failed'
        else:
            status = 'build_failed'
        break
    if command[0] == 'svn': # XXX
        os.chdir('m2crypto')
    
timenow = int(time.time())

os.chdir(cwd)

msg = """tinderbox: tree: M2Crypto
tinderbox: starttime: %(starttime)d
tinderbox: timenow: %(timenow)d
tinderbox: status: success
tinderbox: buildname: %(buildname)s
tinderbox: errorparser: unix
tinderbox: END

""" % {'starttime': starttime, 'timenow': timenow, 'buildname': BUILD_NAME}

msg += open('tbox.log').read()

server = smtplib.SMTP(host=SMTP_SERVER, port=SMTP_PORT)
server.set_debuglevel(1)
server.starttls()
server.login(SMTP_USER, SMTP_PASSWORD)
server.sendmail(FROM_EMAIL, TO_EMAIL, msg)
server.quit()
