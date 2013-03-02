# -*- coding: utf-8 -*-
"""
    Sample Python file, here to test out code coverage in Jenkins.
    ~~~~~~~~~~~~

    DO NOT USE THIS IN PRODUCTION. IT IS NOT SECURE IN ANY WAY.
    YOU HAVE BEEN WARNED.

    :copyright: (c) 2013 by Jarret Raim
    :license: Apache 2.0, see LICENSE for details
"""
def a_sample_method_here():
    foo = "bar"
    i = 1
    if ("bar" == foo):
        print "saw bar"
        i += 2
    else:
        print "not bar"
        i += 4
    print "total",i

a_sample_method_here()  # Do something coverage can chew on.
