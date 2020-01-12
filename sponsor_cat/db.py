

def get_db_conn():
    max_retries = int(os.environ.get('DB_CONN_MAX_RETRY', 5))

    def _get_conn():
        conn = psycopg2.connect(os.environ['DATABASE_URL'])
        conn.set_session(autocommit=True)
        return conn

    if not getattr(app, 'conn', None):
        for r in range(1, max_retries + 1):
            try:
                setattr(app, 'conn',  _get_conn())
                return app.conn
            except psycopg2.OperationalError:
                app.logger.exception('Failed to create db conn retry:%s', r)
                if r == max_retries:
                    raise
    return app.conn


def get_cursor(*args, **kwargs):
    try:
        conn = get_db_conn()
        cur = conn.cursor(*args, **kwargs)
        return cur
    except (psycopg2.InterfaceError, psycopg2.OperationalError):
        app.logger.info('Refreshing db connection')
        app.conn = None
        conn = get_db_conn()
        return conn.cursor(*args, **kwargs)


def execute_sql(*sql_dict, raise_error=None, cursor_factory=None):
    result = None
    error = None
    app.logger.debug('Running query %r', sql_dict)
    try:
        with get_cursor(cursor_factory=cursor_factory) as cur:
            for sql in sql_dict:
                if sql.get('values'):
                    cur.execute(sql['sql'], sql['values'])
                else:
                    cur.execute(sql['sql'])
                if sql.get('fetchall') is True:
                    result = cur.fetchall()
                elif sql.get('fetchone') is True:
                    result = cur.fetchone()
                else:
                    pass
            cur.close()
    except psycopg2.Error as e:
        error = e
        app.logger.exception('Encountered db error sql: %r', sql_dict)
    except Exception as e:
        error = e
        app.logger.exception('Encountered unknown error sql: %r', sql_dict)
    if raise_error and isinstance(error, raise_error):
        raise error
    return result

