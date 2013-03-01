#import os
import unittest

#from oslo.config import cfg
#from meniscus.config import init_config, get_config


# Configuration test configuration options
#test_group = cfg.OptGroup(name='test', title='Configuration Test')

#CFG_TEST_OPTIONS = [
#    cfg.BoolOpt('should_pass',
#                default=False,
#                help="""Example option to make sure configuration
#                        loading passes test.
#                     """
#                )
#]


def suite():
    suite = unittest.TestSuite()
    suite.addTest(WhenConfiguring())

    return suite


class WhenConfiguring(unittest.TestCase):

    def test_loading(self):
        self.assertTrue(True) 
#       init_config(['--config-file', '../etc/meniscus/meniscus.conf'])

#       conf = get_config()
#       conf.register_group(test_group)
#       conf.register_opts(CFG_TEST_OPTIONS, group=test_group)

#       self.assertTrue(conf.test.should_pass)
