"""M2Crypto Version Info"""

RCS_id='$Id: _version.py,v 1.4 2004/04/12 02:07:28 ngps Exp $'

import string
version_info = (0, 13, 2)
version = string.join(map(lambda x: "%s" % x, version_info), ".")

