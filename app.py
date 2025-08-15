import os, secrets, smtplib, hashlib, time, base64
from email.message import EmailMessage
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect, generate_csrf
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash

from flask_session import Session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman

from cryptography.fernet import Fernet, InvalidToken

from models import db, User, VaultEntry
from crypto_util import derive_key, generate_salt


# ---------- Config ----------
def create_app():
    app = Flask(__name__, instance_relative_config=True)

    # Secrets & DB
    app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")

    db_url = os.environ.get("DATABASE_URL")
    if db_url:
        if db_url.startswith("postgres://"):
            db_url = db_url.replace("postgres://", "postgresql+psycopg://", 1)
        elif db_url.startswith("postgresql://"):
            db_url = db_url.replace("postgresql://", "postgresql+psycopg://", 1)
        app.config["SQLALCHEMY_DATABASE_URI"] = db_url
    else:
        os.makedirs(app.instance_path, exist_ok=True)
        app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{os.path.join(app.instance_path, 'app.db')}"

    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # --- Security: cookies & sessions ---
    app.config.update(
        SESSION_TYPE="filesystem",  # server-side session storage
        SESSION_FILE_DIR=os.path.join(app.instance_path, "flask_session"),
        SESSION_PERMANENT=False,
        PERMANENT_SESSION_LIFETIME=1800,  # 30 minutes
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        WTF_CSRF_TIME_LIMIT=1800,  # CSRF token lifetime
    )
    os.makedirs(app.config["SESSION_FILE_DIR"], exist_ok=True)

    # Init extensions
    db.init_app(app)
    Session(app)

    # CSRF protection
    CSRFProtect(app)

    # Rate limits
    Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

    # Security headers / HTTPS
    csp = {
        "default-src": "'self'",
        "img-src": ["'self'", "data:"],
        "style-src": ["'self'", "'unsafe-inline'"],  # you use inline styles
        "script-src": ["'self'"],
        "font-src": ["'self'", "data:"],
    }
    Talisman(
        app,
        content_security_policy=csp,
        force_https=True,
        strict_transport_security=True,
        frame_options="DENY",
        referrer_policy="no-referrer",
        session_cookie_secure=True,
        content_security_policy_nonce_in=["script-src"],
    )

    with app.app_context():
        db.create_all()

    # Make csrf_token() available in templates for non-WTF forms
    @app.context_processor
    def inject_csrf():
        return dict(csrf_token=lambda: generate_csrf())

    return app


app = create_app()


# ---------- Forms ----------
class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=255)])
    login_password = PasswordField("Login Password", validators=[DataRequired(), Length(min=8, max=128)])
    master_password = PasswordField("Master Password (for vault encryption)", validators=[DataRequired(), Length(min=8, max=128)])
    submit = SubmitField("Create account")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=255)])
    login_password = PasswordField("Login Password", validators=[DataRequired(), Length(min=8, max=128)])
    submit = SubmitField("Log in")


class EntryForm(FlaskForm):
    account = StringField("Account", validators=[DataRequired(), Length(min=1, max=255)])
    username = StringField("Username", validators=[DataRequired(), Length(min=1, max=255)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=1, max=255)])
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
    sender_email = os.environ["SMTP_SENDER_EMAIL"]
    app_password = os.environ["SMTP_APP_PASSWORD"]

    msg = EmailMessage()
    msg.set_content(f"Your 2FA code is: {code}\n\nThis code expires in 3 minutes.")
    msg["Subject"] = "Your 2FA Code"
    msg["From"] = sender_email
    msg["To"] = recipient_email

    with smtplib.SMTP("smtp.gmail.com", 587) as smtp:
        smtp.starttls()
        smtp.login(sender_email, app_password)
        smtp.send_message(msg)


def _store_one_time_code(prefix: str, code: str, ttl_seconds: int = 180):
    """Stores a hash of the code + secret with an expiry (one-time use)."""
    h = hashlib.sha256((code + app.config["SECRET_KEY"]).encode()).hexdigest()
    session[f"{prefix}_code_hash"] = h
    session[f"{prefix}_code_exp"] = int(time.time()) + ttl_seconds
    session.modified = True


def _verify_one_time_code(prefix: str, submitted: str) -> bool:
    exp = session.get(f"{prefix}_code_exp")
    if not exp or time.time() > exp:
        return False
    expected = session.get(f"{prefix}_code_hash")
    cand = hashlib.sha256((submitted + app.config["SECRET_KEY"]).encode()).hexdigest()
    ok = expected and secrets.compare_digest(cand, expected)
    # one-time: remove regardless
    session.pop(f"{prefix}_code_hash", None)
    session.pop(f"{prefix}_code_exp", None)
    return bool(ok)


def _store_session_fernet_key(master_password: str, user: User):
    """Derive Fernet key from master password and user's salt; store base64 key server-side."""
    key = derive_key(master_password, user.kdf_salt)             # bytes
    session["fernet_key_b64"] = base64.urlsafe_b64encode(key).decode()  # str


def _get_fernet_from_session() -> Fernet | None:
    b64 = session.get("fernet_key_b64")
    if not b64:
        return None
    try:
        return Fernet(b64.encode())
    except Exception:
        return None


# ---------- Routes ----------
@app.route("/")
def index():
    if current_user():
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


from flask_limiter import Limiter  # noqa: E402  (already imported; keeps linters happy)


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

        session["user_id"] = user.id
        _store_session_fernet_key(form.master_password.data, user)  # store derived key, not the password
        flash("Account created. You are logged in.", "success")
        return redirect(url_for("dashboard"))
    return render_template("register.html", form=form)


from flask_limiter.util import get_remote_address  # noqa: E402


@app.route("/login", methods=["GET", "POST"])
def login():
    # Per-IP limit for login attempts
    limiter = Limiter(get_remote_address)
    limiter.limit("5/minute; 20/hour")(lambda: None)()  # attach limit to this call

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if not user or not check_password_hash(user.pw_hash, form.login_password.data):
            flash("Invalid credentials.", "error")
            return redirect(url_for("login"))

        code = f"{secrets.randbelow(1_000_000):06}"
        session["pending_user_id"] = user.id
        _store_one_time_code("login", code, ttl_seconds=180)
        try:
            send_code_to_email(user.email, code)
        except Exception:
            flash("Could not send 2FA email. Check SMTP env vars.", "error")
            return redirect(url_for("login"))
        return redirect(url_for("verify_login"))
    return render_template("login.html", form=form)


@app.route("/verify-login", methods=["GET", "POST"])
def verify_login():
    # Rate limit too
    limiter = Limiter(get_remote_address)
    limiter.limit("6/minute; 30/hour")(lambda: None)()

    if "pending_user_id" not in session:
        return redirect(url_for("login"))
    form = TwoFAForm()
    if form.validate_on_submit():
        if _verify_one_time_code("login", form.code.data):
            user = User.query.get(session.pop("pending_user_id"))
            if not user:
                flash("Login flow expired. Try again.", "error")
                return redirect(url_for("login"))
            session["user_id"] = user.id
            flash("Login verified. Enter your master password to access vault.", "success")
            return redirect(url_for("dashboard"))
        flash("Incorrect or expired code.", "error")
    return render_template("reveal.html", form=form, prompt="Enter the 6-digit code we emailed to you")


@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    # Accept master password, convert to fernet key, store server-side
    if request.method == "POST":
        mpw = request.form.get("master_password", "")
        if not mpw or len(mpw) < 8:
            flash("Provide your master password (min 8 chars) to continue.", "error")
        else:
            _store_session_fernet_key(mpw, current_user())
            flash("Master password accepted for this session.", "success")

    entries = (
        VaultEntry.query.filter_by(user_id=current_user().id)
        .order_by(VaultEntry.created_at.desc())
        .all()
    )
    return render_template("dashboard.html", entries=entries, has_master=("fernet_key_b64" in session))


@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    if "fernet_key_b64" not in session:
        flash("Enter master password on the dashboard first.", "error")
        return redirect(url_for("dashboard"))

    form = EntryForm()
    if form.validate_on_submit():
        f = _get_fernet_from_session()
        if not f:
            flash("Session key missing. Re-enter your master password.", "error")
            return redirect(url_for("dashboard"))
        ct = f.encrypt(form.password.data.encode())
        ve = VaultEntry(user_id=current_user().id, account=form.account.data, username=form.username.data, password_ct=ct)
        db.session.add(ve)
        db.session.commit()
        flash("Entry saved.", "success")
        return redirect(url_for("dashboard"))
    return render_template("add_entry.html", form=form)


@app.route("/reveal/<int:entry_id>", methods=["GET", "POST"])
@login_required
def reveal(entry_id):
    # Per-IP rate-limit reveals (mail + verify)
    limiter = Limiter(get_remote_address)
    limiter.limit("3/minute; 15/hour")(lambda: None)()

    entry = VaultEntry.query.filter_by(id=entry_id, user_id=current_user().id).first_or_404()

    # Step 1: send code
    if request.method == "GET":
        code = f"{secrets.randbelow(1_000_000):06}"
        session["reveal_entry_id"] = entry_id
        _store_one_time_code("reveal", code, ttl_seconds=180)
        try:
            send_code_to_email(current_user().email, code)
        except Exception:
            flash("Could not send 2FA email.", "error")
            return redirect(url_for("dashboard"))
        form = TwoFAForm()
        return render_template("reveal.html", form=form, prompt="Enter the 6-digit code to reveal the password")

    # Step 2: verify and show decrypted (no flash)
    form = TwoFAForm()
    if form.validate_on_submit():
        if entry_id != session.get("reveal_entry_id"):
            abort(400)
        if not _verify_one_time_code("reveal", form.code.data):
            flash("Incorrect or expired code.", "error")
            return redirect(url_for("dashboard"))
        f = _get_fernet_from_session()
        if not f:
            flash("Enter master password on the dashboard first.", "error")
            return redirect(url_for("dashboard"))
        try:
            pw = f.decrypt(entry.password_ct).decode()
        except InvalidToken:
            flash("Master password incorrect for this vault.", "error")
            return redirect(url_for("dashboard"))

        session.pop("reveal_entry_id", None)
        # IMPORTANT: render on page; do NOT flash/store plaintext in session
        return render_template("reveal.html", decrypted=pw, prompt="Password revealed")

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
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=os.environ.get("FLASK_DEBUG", "0") == "1",
    )
