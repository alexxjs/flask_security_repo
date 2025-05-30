# init_db.py

from flask import Flask
from config import Config
from models import db

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

with app.app_context():
    db.drop_all()      
    db.create_all()   
    print("New database initialized successfully.")
