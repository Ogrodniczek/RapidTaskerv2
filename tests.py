from flask.ext.testing import TestCase
from app import db, app
import unittest
import os


class RapidTaskerTest(TestCase):

    def create_app(self):
        return app

    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = \
            'sqlite://{0}/test.db'.format(os.path.dirname(__file__))
        self.app = app.test_client()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()


if __name__ == '__main__':
    unittest.main()
