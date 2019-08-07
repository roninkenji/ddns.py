from flask import Flask

def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        DEBUG=False,
        DOMAIN='example.com'
    )
    app.config.from_pyfile('config.py', silent=True)
    from . import endpoints
    app.register_blueprint(endpoints.bp)
    app.add_url_rule('/', endpoint='index')
 
    return app
