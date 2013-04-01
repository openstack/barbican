from sqlalchemy.orm.exc import NoResultFound, MultipleResultsFound

from barbican.model.tenant import Tenant, Secret


def _empty_condition():
    pass


def find_tenant(db_session, id=None, username=None,
                when_not_found=_empty_condition,
                when_multiple_found=_empty_condition):
    try:
        if id:
            return db_session.query(Tenant).filter_by(id=id).one()
        elif username:
            return db_session.query(Tenant).filter_by(username=username).one()
    except NoResultFound:
        when_not_found()
    except MultipleResultsFound:
        when_multiple_found()

    return None


def find_secret(db_session, id, when_not_found=_empty_condition,
              when_multiple_found=_empty_condition):
    try:
        return db_session.query(Secret).filter_by(id=id).one()
    except NoResultFound:
        when_not_found()
    except MultipleResultsFound:
        when_multiple_found()
