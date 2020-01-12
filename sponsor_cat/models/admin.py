import hashlib
import uuid

from ..db import execute_sql


class User:
    def __init__(self, email, password=None):
        self.email = email
        self.password = password

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        data = execute_sql({'sql': 'SELECT id, password_hash, salt'
                                   '  FROM users'
                                   ' WHERE email=%s;',
                            'values': [self.email],
                            'fetchone': True})
        if data:
            pw_hash = hashlib.sha256(
                f'{self.password}{data[2]}'.encode()).hexdigest()
            if pw_hash == data[1]:
                return data[0]
        return str(uuid.uuid4())
