"""M2Crypto Version Info"""

RCS_id='$Id: _version.py,v 1.2 2004/03/25 06:33:29 ngps Exp $'

import string
version_info = (0, 13)
version = string.join(map(lambda x: "%s" % x, version_info), ".")

