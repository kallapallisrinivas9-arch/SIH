import os
import tempfile
import pytest
from app import create_app
from config import Config


@pytest.fixture()
def app(tmp_path):
    database = str(tmp_path / "sentinel-test.db")
    TestConfig = type("TestConfig", (Config,), {"TESTING": True, "SECRET_KEY": "test-key", "SQLALCHEMY_DATABASE_URI": f"sqlite:///{database}"})
    application = create_app(TestConfig)
    yield application


@pytest.fixture()
def client(app):
    return app.test_client()


def csrf(client):
    with client.session_transaction() as session:
        session["csrf_token"] = "test-token"
    return "test-token"
