"""GuardedFile.__init__

Copyright (c) 2000 Ng Pheng Siong. All rights reserved.
This software is released under the ZPL."""

RCS_id = '$Id$'
__version__ = '$Revision: 1.1 $'[11:-2]

import GuardedFile

def initialize(context):
    try:
        context.registerClass(
            GuardedFile.GuardedFile,
            constructors=(GuardedFile.manage_addForm, GuardedFile.manage_addGuardedFile)
            #icon='folder.gif'
            )
        context.registerBaseClass(GuardedFile.GuardedFile)

    except:
        import sys, traceback, string
        type, val, tb = sys.exc_info()
        sys.stderr.write(string.join(
            traceback.format_exception(type, val, tb),''))
        del type, val, tb

