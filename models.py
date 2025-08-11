from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    email       = db.Column(db.String(255), unique=True, nullable=False)
    pw_hash     = db.Column(db.String(255), nullable=False)    # login password hash
    kdf_salt    = db.Column(db.LargeBinary, nullable=False)    # salt for vault key derivation
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)

class VaultEntry(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    account     = db.Column(db.String(255), nullable=False)
    username    = db.Column(db.String(255), nullable=False)
    password_ct = db.Column(db.LargeBinary, nullable=False)    # encrypted password
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
