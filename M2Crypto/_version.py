"""M2Crypto Version Info"""

RCS_id='$Id: _version.py,v 1.5 2004/06/30 07:48:20 ngps Exp $'

import string
version_info = (0, 14, 's1')
version = string.join(map(lambda x: "%s" % x, version_info), ".")

