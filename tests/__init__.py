import logging

from platform import linux_distribution

distro_string = linux_distribution(supported_dists=('redhat', 'fedora',
                                                    'debian'),
                                   full_distribution_name=False)[0]
plat_fedora = distro_string in ['redhat', 'fedora']
plat_debian = distro_string in ['debian']
logging.basicConfig(format='%(levelname)s:%(funcName)s:%(message)s',
                    level=logging.DEBUG)
