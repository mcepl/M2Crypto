"""M2Crypto Version Info"""

RCS_id='$Id: _version.py,v 1.1 2004/03/21 13:47:44 ngps Exp $

import string
version_info = (0, 13)
version = string.join(map(lambda x: "%s" % x, version_info), ".")

