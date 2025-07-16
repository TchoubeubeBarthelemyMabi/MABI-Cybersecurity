from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import os, binascii, hashlib, hmac

# Initialisation à connecter dans app.py via db.init_app(app)
db = SQLAlchemy()

class User(db.Model, UserMixin):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    api_key_hash = db.Column(db.String(64), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, pwd):
        """Hash le mot de passe et le stocke."""
        self.password_hash = generate_password_hash(pwd)

    def check_password(self, pwd):
        """Vérifie si le mot de passe est correct."""
        return check_password_hash(self.password_hash, pwd)

    def generate_api_key(self):
        """Génère une clé API unique et la stocke en version hashée."""
        key = binascii.hexlify(os.urandom(24)).decode()
        self.api_key_hash = hashlib.sha256(key.encode()).hexdigest()
        db.session.commit()
        return key

    def check_api_key(self, key):
        """Vérifie que la clé API fournie correspond à celle stockée."""
        if not self.api_key_hash:
            return False
        return hmac.compare_digest(self.api_key_hash, hashlib.sha256(key.encode()).hexdigest())
