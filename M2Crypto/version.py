"""M2Crypto Version Info"""

RCS_id='$Id: version.py,v 1.1 2004/03/21 13:19:19 ngps Exp $'

import string
version_info = (0, 13)
version = string.join(map(lambda x: "%s" % x, version_info), ".")

