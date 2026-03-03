import os
from sqlalchemy import create_engine
from sqlalchemy.engine import URL
from argon2 import PasswordHasher

# Argon2id hasher — OWASP-recommended parameters.
# One-way: irrecoverable by users or service operators.
# time_cost=3, memory_cost=65536 KB (64 MB), parallelism=4
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

_DB_USER = os.environ.get('DB_USER')
_DB_PASS = os.environ.get('DB_PASS')
_DB_NAME = os.environ.get('DB_NAME')
_DB_HOST = os.environ.get('DB_HOST')


def _get_db_url():
    """
    Constructs the SQLAlchemy URL.
    Handles Unix Sockets for Cloud Run and TCP for local development.
    """
    if _DB_HOST and _DB_HOST.startswith('/'):
        # Unix Socket (Google Cloud Run)
        return URL.create(
            drivername="mysql+pymysql",
            username=_DB_USER,
            password=_DB_PASS,
            database=_DB_NAME,
            query={"unix_socket": _DB_HOST}
        )
    else:
        # TCP Connection (Local Dev / External IP)
        return URL.create(
            drivername="mysql+pymysql",
            username=_DB_USER,
            password=_DB_PASS,
            host=_DB_HOST or "127.0.0.1",
            database=_DB_NAME
        )


# Single shared engine — pool_pre_ping checks the connection before use
engine = create_engine(
    _get_db_url(),
    pool_size=5,
    max_overflow=2,
    pool_timeout=30,
    pool_recycle=1800,
    pool_pre_ping=True
)
