import logging
import os.path
import sys

from platform import linux_distribution

if sys.version_info[:2] <= (2, 6):
    sys.path.insert(0, os.path.join(os.path.abspath(os.path.dirname(__file__)),
                                    'vendor'))

distro_string = linux_distribution(supported_dists=('redhat', 'fedora',
                                                    'debian'),
                                   full_distribution_name=False)[0]
plat_fedora = distro_string in ['redhat', 'fedora']
plat_debian = distro_string in ['debian']
logging.basicConfig(format='%(levelname)s:%(funcName)s:%(message)s',
                    level=logging.DEBUG)
