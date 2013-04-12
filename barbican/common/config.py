import os
from oslo.config import cfg
from barbican.openstack.common import log

# Ensure the local python config path is on the list to pull config info from
CONF_FILES = cfg.find_config_files(prog='barbican-api')
print ">>>>>>> "
print CONF_FILES
#CONF_FILES = cfg.find_config_files(project='barbican', prog='barbican-api')
CONF_FILES.append('./etc/barbican-api.conf')
CONF_FILES.append('../etc/barbican-api.conf')
CONF_FILES = [cfile for cfile in CONF_FILES if os.path.isfile(cfile)]

# Set configuration files
CONF = cfg.CONF
CONF(prog='barbican-api', default_config_files=CONF_FILES)
#CONF(project='barbican', prog='barbican-api', default_config_files=CONF_FILES)
