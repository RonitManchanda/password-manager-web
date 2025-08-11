import secrets, smtplib, os
from email.message import EmailMessage
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet, InvalidToken

from models import db, User, VaultEntry
from crypto_util import derive_key, generate_salt


# ---------- Config ----------
def create_app():
    app = Flask(__name__, instance_relative_config=True)
    app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")

    # Prefer managed Postgres in production; fall back to local SQLite
    db_url = os.environ.get("DATABASE_URL")
    if db_url:
        # Normalize and force psycopg v3 driver for SQLAlchemy
        if db_url.startswith("postgres://"):
            db_url = db_url.replace("postgres://", "postgresql+psycopg://", 1)
        elif db_url.startswith("postgresql://"):
            db_url = db_url.replace("postgresql://", "postgresql+psycopg://", 1)
        app.config["SQLALCHEMY_DATABASE_URI"] = db_url
    else:
        os.makedirs(app.instance_path, exist_ok=True)
        app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{os.path.join(app.instance_path, 'app.db')}"

    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)
    with app.app_context():
        db.create_all()
    return app


app = create_app()


# ---------- Forms ----------
class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    login_password = PasswordField("Login Password", validators=[DataRequired(), Length(min=8)])
    master_password = PasswordField("Master Password (for vault encryption)",
                                    validators=[DataRequired(), Length(min=8)])
    submit = SubmitField("Create account")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    login_password = PasswordField("Login Password", validators=[DataRequired()])
    submit = SubmitField("Log in")


class EntryForm(FlaskForm):
    account = StringField("Account", validators=[DataRequired()])
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Save")


class TwoFAForm(FlaskForm):
    code = StringField("Enter the 6-digit code", validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField("Verify")


# ---------- Helpers ----------
def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return User.query.get(uid)


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def send_code_to_email(recipient_email: str, code: str):
    """
    Sends the 2FA code via SMTP using env vars:
      - SMTP_SENDER_EMAIL
      - SMTP_APP_PASSWORD
    """
    sender_email = os.environ["SMTP_SENDER_EMAIL"]
    app_password = os.environ["SMTP_APP_PASSWORD"]

    msg = EmailMessage()
    msg.set_content(f"Your 2FA code is: {code}")
    msg["Subject"] = "Your 2FA Code"
    msg["From"] = sender_email
    msg["To"] = recipient_email

    with smtplib.SMTP("smtp.gmail.com", 587) as smtp:
        smtp.starttls()
        smtp.login(sender_email, app_password)
        smtp.send_message(msg)


def derive_fernet(master_password: str, kdf_salt: bytes) -> Fernet:
    key = derive_key(master_password, kdf_salt)
    return Fernet(key)


# ---------- Routes ----------
@app.route("/")
def index():
    if current_user():
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data.lower()).first():
            flash("Email already registered.", "error")
            return redirect(url_for("register"))

        kdf_salt = generate_salt()
        user = User(
            email=form.email.data.lower(),
            pw_hash=generate_password_hash(form.login_password.data),
            kdf_salt=kdf_salt,
        )
        db.session.add(user)
        db.session.commit()

        # Store the master password in session TEMPORARILY to allow first login flow
        session["user_id"] = user.id
        session["master_password"] = form.master_password.data  # not persisted!
        flash("Account created. You are logged in.", "success")
        return redirect(url_for("dashboard"))
    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if not user or not check_password_hash(user.pw_hash, form.login_password.data):
            flash("Invalid credentials.", "error")
            return redirect(url_for("login"))

        # Step 1: set pending login and send code
        code = f"{secrets.randbelow(1_000_000):06}"
        session["pending_user_id"] = user.id
        session["pending_login_code"] = code
        try:
            send_code_to_email(user.email, code)
        except Exception:
            flash("Could not send 2FA email. Check SMTP env vars.", "error")
            return redirect(url_for("login"))
        return redirect(url_for("verify_login"))
    return render_template("login.html", form=form)


@app.route("/verify-login", methods=["GET", "POST"])
def verify_login():
    if "pending_user_id" not in session:
        return redirect(url_for("login"))
    form = TwoFAForm()
    if form.validate_on_submit():
        if form.code.data == session.get("pending_login_code"):
            session["user_id"] = session.pop("pending_user_id")
            session.pop("pending_login_code", None)
            # Ask for master password once per session (for decrypting)
            flash("Login verified. Enter your master password to access vault.", "success")
            return redirect(url_for("dashboard"))
        flash("Incorrect code.", "error")
    return render_template("reveal.html", form=form, prompt="Enter the 6-digit code we emailed to you")


@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    # ensure master password is in session for decrypt/encrypt in this sample
    if request.method == "POST":
        mpw = request.form.get("master_password", "")
        if not mpw or len(mpw) < 8:
            flash("Provide your master password (min 8 chars) to continue.", "error")
        else:
            session["master_password"] = mpw
            flash("Master password accepted for this session.", "success")
    entries = VaultEntry.query.filter_by(user_id=current_user().id).order_by(VaultEntry.created_at.desc()).all()
    return render_template("dashboard.html", entries=entries, has_master=("master_password" in session))


@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    if "master_password" not in session:
        flash("Enter master password on the dashboard first.", "error")
        return redirect(url_for("dashboard"))

    form = EntryForm()
    if form.validate_on_submit():
        user = current_user()
        f = derive_fernet(session["master_password"], user.kdf_salt)
        ct = f.encrypt(form.password.data.encode())
        ve = VaultEntry(user_id=user.id, account=form.account.data, username=form.username.data, password_ct=ct)
        db.session.add(ve)
        db.session.commit()
        flash("Entry saved.", "success")
        return redirect(url_for("dashboard"))
    return render_template("add_entry.html", form=form)


@app.route("/reveal/<int:entry_id>", methods=["GET", "POST"])
@login_required
def reveal(entry_id):
    entry = VaultEntry.query.filter_by(id=entry_id, user_id=current_user().id).first_or_404()

    # send code, ask for it, then decrypt
    if request.method == "GET":
        code = f"{secrets.randbelow(1_000_000):06}"
        session["reveal_code"] = code
        session["reveal_entry_id"] = entry_id
        try:
            send_code_to_email(current_user().email, code)
        except Exception:
            flash("Could not send 2FA email.", "error")
            return redirect(url_for("dashboard"))
        form = TwoFAForm()
        return render_template("reveal.html", form=form, prompt="Enter the 6-digit code to reveal the password")

    # POST: verify code and show decrypted password
    form = TwoFAForm()
    if form.validate_on_submit():
        if entry_id != session.get("reveal_entry_id"):
            abort(400)
        if form.code.data != session.get("reveal_code"):
            flash("Incorrect code.", "error")
            return redirect(url_for("dashboard"))
        if "master_password" not in session:
            flash("Enter master password on the dashboard first.", "error")
            return redirect(url_for("dashboard"))

        user = current_user()
        try:
            f = derive_fernet(session["master_password"], user.kdf_salt)
            pw = f.decrypt(entry.password_ct).decode()
        except InvalidToken:
            flash("Master password incorrect for this vault.", "error")
            return redirect(url_for("dashboard"))

        # one-time reveal: clear code
        session.pop("reveal_code", None)
        session.pop("reveal_entry_id", None)
        flash(f"Decrypted password: {pw}", "info")
        return redirect(url_for("dashboard"))
    return render_template("reveal.html", form=form, prompt="Enter the 6-digit code")


@app.route("/delete/<int:entry_id>", methods=["POST"])
@login_required
def delete(entry_id):
    entry = VaultEntry.query.filter_by(id=entry_id, user_id=current_user().id).first_or_404()
    db.session.delete(entry)
    db.session.commit()
    flash("Entry deleted.", "success")
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    # Local dev convenience. In Render you’ll run via gunicorn (Procfile).
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=os.environ.get("FLASK_DEBUG", "0") == "1",
    )
