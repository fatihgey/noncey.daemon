"""
Shared config and database helpers used by both app.py and admin.py.
"""

import configparser
import os
import sqlite3

from flask import g

CONFIG_PATH = os.environ.get('NONCEY_CONF', '/etc/noncey/noncey.conf')
_cfg: configparser.ConfigParser | None = None


def get_config() -> configparser.ConfigParser:
    global _cfg
    if _cfg is None:
        _cfg = configparser.ConfigParser()
        _cfg.read(CONFIG_PATH)
    return _cfg


def cfg(section: str, key: str, fallback=None):
    return get_config().get(section, key, fallback=fallback)


def get_db() -> sqlite3.Connection:
    if 'db' not in g:
        conn = sqlite3.connect(
            cfg('paths', 'db_path', fallback='/var/lib/noncey/noncey.db')
        )
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA foreign_keys = ON')
        g.db = conn
    return g.db
