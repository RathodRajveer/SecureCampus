import os
from functools import wraps

import jwt
from jwt import PyJWKClient
from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    session,
    request,
    flash,
)
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv

from db import (
    get_db_connection,
    initialize_audit_table,
    log_audit_event,
)

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]
initialize_audit_table()
KEYCLOAK_SERVER_URL = os.environ["KEYCLOAK_SERVER_URL"].rstrip("/")
KEYCLOAK_REALM = os.environ["KEYCLOAK_REALM"]
KEYCLOAK_CLIENT_ID = os.environ["KEYCLOAK_CLIENT_ID"]

KEYCLOAK_ISSUER = (
    f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}"
)
JWKS_URL = (
    f"{KEYCLOAK_ISSUER}/protocol/openid-connect/certs"
)

jwks_client = PyJWKClient(JWKS_URL)

oauth = OAuth(app)

oauth.register(
    name="keycloak",
    client_id=KEYCLOAK_CLIENT_ID,
    client_secret=os.environ["KEYCLOAK_CLIENT_SECRET"],
    server_metadata_url=(
        f"{KEYCLOAK_ISSUER}/.well-known/openid-configuration"
    ),
    client_kwargs={"scope": "openid profile email"},
)


def role_required(required_role):
    """Restrict a route to users with the required Keycloak realm role."""
    def decorator(view_function):
        @wraps(view_function)
        def wrapped_view(*args, **kwargs):
            if "user" not in session:
                return redirect(url_for("login"))

            roles = session["user"].get("roles", [])
            if required_role not in roles:
                return (
                    "403 Forbidden: You do not have permission "
                    "to access this page.",
                    403,
                )

            return view_function(*args, **kwargs)

        return wrapped_view
    return decorator


@app.route("/")
def home():
    return render_template("index.html", user=session.get("user"))


@app.route("/login")
def login():
    redirect_uri = url_for("callback", _external=True)
    return oauth.keycloak.authorize_redirect(redirect_uri)


@app.route("/callback")
def callback():
    token = oauth.keycloak.authorize_access_token()

    user_info = token.get("userinfo")
    if not user_info:
        user_info = oauth.keycloak.userinfo()

    access_token = token.get("access_token")
    if not access_token:
        return "Login failed: Keycloak did not return an access token.", 400

    # Verify the access token's signature, issuer, and expiration.
    try:
        signing_key = jwks_client.get_signing_key_from_jwt(access_token)
        decoded_token = jwt.decode(
            access_token,
            signing_key.key,
            algorithms=["RS256"],
            issuer=KEYCLOAK_ISSUER,
          options={
    "verify_signature": True,
    "verify_exp": True,
    "verify_iss": True,
    "verify_aud": True,
},
audience=KEYCLOAK_CLIENT_ID,
        )
    except (jwt.PyJWTError, Exception):
        app.logger.exception("Access-token verification failed")
        return "Login failed: Access token could not be verified.", 401

    roles = decoded_token.get("realm_access", {}).get("roles", [])

    session.clear()
    session["user"] = {
        "username": user_info.get("preferred_username", ""),
        "name": user_info.get("name", ""),
        "email": user_info.get("email", ""),
        "roles": roles,
    }

    return redirect(url_for("home"))


@app.route("/student")
@role_required("STUDENT")
def student_portal():
    return render_template("student.html", user=session["user"])


@app.route("/faculty")
@role_required("FACULTY")
def faculty_portal():
    return render_template("faculty.html", user=session["user"])


@app.route("/admin-dashboard")
@role_required("ADMIN")
def admin_dashboard():
    return render_template("admin.html", user=session["user"])



@app.route("/admin/students", methods=["GET", "POST"])
@role_required("ADMIN")
def admin_students():
    if request.method == "POST":
        username = request.form.get("keycloak_username", "").strip()
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip()
        department = request.form.get("department", "").strip()

        if not all([username, full_name, email, department]):
            flash("Please fill in all fields.", "error")
            return redirect(url_for("admin_students"))

        conn = get_db_connection()
        try:
            existing = conn.execute(
                "SELECT id FROM students WHERE keycloak_username = ?",
                (username,),
            ).fetchone()

            if existing:
                log_audit_event(
                    session["user"]["username"],
                    "STUDENT_CREATE_REJECTED",
                    f"Duplicate student username submitted: {username}",
                    "FAILED",
                )
                flash(
                    "A student record with this username already exists.",
                    "error",
                )
            else:
                conn.execute(
                    """
                    INSERT INTO students
                        (keycloak_username, full_name, email, department)
                    VALUES (?, ?, ?, ?)
                    """,
                    (username, full_name, email, department),
                )
                conn.commit()

                log_audit_event(
                    session["user"]["username"],
                    "STUDENT_CREATED",
                    f"Added student record: {username}",
                    "SUCCESS",
                )
                flash("Student record added successfully.", "success")

        except Exception:
            app.logger.exception("Student record operation failed")
            flash("Could not save the student record.", "error")
        finally:
            conn.close()

        return redirect(url_for("admin_students"))

    conn = get_db_connection()
    try:
        students = conn.execute(
            """
            SELECT id, keycloak_username, full_name, email, department, created_at
            FROM students
            ORDER BY id
            """
        ).fetchall()
    finally:
        conn.close()

    return render_template("admin_students.html", students=students)


@app.route("/logout")
def logout():
    session.clear()
    post_logout_uri = "http://127.0.0.1:5000/"

    from urllib.parse import urlencode

    logout_url = (
        f"{KEYCLOAK_ISSUER}/protocol/openid-connect/logout?"
        + urlencode({
            "client_id": KEYCLOAK_CLIENT_ID,
            "post_logout_redirect_uri": post_logout_uri,
        })
    )
    return redirect(logout_url)


@app.route("/admin/audit")
@role_required("ADMIN")
def admin_audit():
    log_audit_event(
        session["user"]["username"],
        "AUDIT_PAGE_VIEWED",
        "Admin opened Audit & Reports",
        "SUCCESS",
    )

    conn = get_db_connection()
    try:
        logs = conn.execute(
            """
            SELECT id, username, action, details, status, created_at
            FROM audit_logs
            ORDER BY id DESC
            LIMIT 200
            """
        ).fetchall()
    finally:
        conn.close()

    return render_template("audit.html", logs=logs)

@app.route("/admin/governance")
@role_required("ADMIN")
def admin_governance():
    conn = get_db_connection()
    try:
        students = conn.execute(
            """
            SELECT id, keycloak_username, full_name, email, department, created_at
            FROM students
            ORDER BY id
            """
        ).fetchall()
    finally:
        conn.close()

    log_audit_event(
        session["user"]["username"],
        "GOVERNANCE_PAGE_VIEWED",
        "Admin opened Access Governance",
        "SUCCESS",
    )

    return render_template("governance.html", students=students)


if __name__ == "__main__":
    app.run(debug=True)
