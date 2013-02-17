# -*- coding: utf-8 -*-
"""
    Barbican Models
    ~~~~~~~~~~~~~~~

    The models for the Barbican application.

    DO NOT USE THIS IN PRODUCTION. IT IS NOT SECURE IN ANY WAY.
    YOU HAVE BEEN WARNED.

    :copyright: (c) 2013 by Jarret Raim
    :license: Apache 2.0, see LICENSE for details
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base

engine = create_engine('sqlite:////tmp/barbican.db', convert_unicode=True)
db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=False,
                                         bind=engine))
Base = declarative_base()
Base.query = db_session.query_property()


def init_db():
    # import all modules here that might define models so that
    # they will be registered properly on the metadata.  Otherwise
    # you will have to import them first before calling init_db()
    import models
    Base.metadata.create_all(bind=engine)
    db_session.add(models.User('admin', 'admin@localhost'))
    db_session.commit()