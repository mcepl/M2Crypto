#!/usr/bin/env python

import os, string, tempfile

search = 's_server -quiet -www'
fn = tempfile.mktemp()
cmd = 'ps | egrep "%s" > %s' % (search, fn)
os.system(cmd)
f = open(fn)
while 1:
    ps = f.readline()
    if not ps:
        break
    chunk = string.split(ps)
    pid, cmd = chunk[0], chunk[4]
    if cmd == string.split(search)[0]:
        os.kill(int(pid), 1)
f.close()
os.unlink(fn)


