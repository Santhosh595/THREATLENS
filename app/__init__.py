from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_limiter import Limiter
import logging

# Initialize extensions
db = SQLAlchemy()
limiter = Limiter()


def create_app():
    app = Flask(__name__)
    # Configuration can be set here
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Initialize extensions
    db.init_app(app)
    limiter.init_app(app)
    CORS(app)

    # Logging setup
    logging.basicConfig(level=logging.INFO)
    @app.before_request
    def log_request():
        app.logger.info('Request: %s %s', request.method, request.path)

    return app
