"""M2Crypto Version Info"""

RCS_id='$Id: _version.py,v 1.3 2004/03/31 01:30:58 ngps Exp $'

import string
version_info = (0, 13, 1)
version = string.join(map(lambda x: "%s" % x, version_info), ".")

