import os
import unittest

from oslo.config import cfg
from barbican.common import config
import logging

# Configuration test configuration options
test_group = cfg.OptGroup(name='test', title='Configuration Test')

CFG_TEST_OPTIONS = [
    cfg.BoolOpt('should_pass',
                default=False,
                help="""Example option to make sure configuration
                        loading passes test.
                     """
                )
]

CONF = cfg.CONF

LOG = logging.getLogger(__name__)

def suite():
    suite = unittest.TestSuite()
    suite.addTest(WhenConfiguring())

    return suite


class WhenConfiguring(unittest.TestCase):

    def test_loading(self):

        LOG.debug("In test 'test_loading'")

        CONF.register_group(test_group)
        CONF.register_opts(CFG_TEST_OPTIONS, group=test_group)

        self.assertTrue(CONF.test.should_pass)


if __name__ == '__main__':
    unittest.main()
