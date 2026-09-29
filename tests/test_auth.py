"""Sign-up, sign-in, recovery and session security."""
from fastapi.testclient import TestClient

from conftest import PASSWORD, last_link_token, signed_in_client, unique_email


def test_signup_requires_email_verification(anon):
    email = unique_email()
    r = anon.post("/api/auth/signup", json={"email": email, "password": PASSWORD,
                                            "org_name": "Verify Co"})
    assert r.status_code == 200 and r.json()["verification_required"] is True
    # No session until the address is proven.
    assert anon.get("/api/auth/me").status_code == 401
    r = anon.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    assert r.status_code == 403 and r.json()["detail"] == "verify_email"

    r = anon.post("/api/auth/verify-email", json={"token": last_link_token(email)})
    assert r.status_code == 200
    me = anon.get("/api/auth/me").json()
    assert me["user"]["email"] == email and me["user"]["role"] == "owner"
    assert me["org"]["name"] == "Verify Co"


def test_verification_link_is_single_use(anon):
    email = unique_email()
    anon.post("/api/auth/signup", json={"email": email, "password": PASSWORD, "org_name": "Once"})
    token = last_link_token(email)
    assert anon.post("/api/auth/verify-email", json={"token": token}).status_code == 200
    assert anon.post("/api/auth/verify-email", json={"token": token}).status_code == 400


def test_signup_does_not_reveal_existing_accounts(app, client):
    """Same response for a taken email as for a new one: no account enumeration."""
    c = TestClient(app)
    taken = c.post("/api/auth/signup", json={"email": client.email, "password": PASSWORD,
                                             "org_name": "Dup"})
    fresh = c.post("/api/auth/signup", json={"email": unique_email(), "password": PASSWORD,
                                             "org_name": "New"})
    assert taken.status_code == fresh.status_code == 200
    assert taken.json() == fresh.json()


def test_weak_passwords_rejected(anon):
    for pw in ("short", "password123", "aaaaaaaaaaaa"):
        r = anon.post("/api/auth/signup", json={"email": unique_email(), "password": pw,
                                                "org_name": "Weak"})
        assert r.status_code == 422, pw


def test_invalid_email_rejected(anon):
    r = anon.post("/api/auth/signup", json={"email": "not-an-email", "password": PASSWORD,
                                            "org_name": "X"})
    assert r.status_code == 422


def test_login_logout_cycle(app):
    c = signed_in_client(app)
    assert c.post("/api/auth/logout").status_code == 200
    assert c.get("/api/auth/me").status_code == 401
    r = c.post("/api/auth/login", json={"email": c.email, "password": PASSWORD})
    assert r.status_code == 200
    assert c.get("/api/auth/me").status_code == 200


def test_login_errors_are_identical_for_unknown_and_wrong_password(app, client):
    c = TestClient(app)
    unknown = c.post("/api/auth/login", json={"email": unique_email(), "password": PASSWORD})
    wrong = c.post("/api/auth/login", json={"email": client.email, "password": "wrong-password-1"})
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json() == wrong.json()


def test_repeated_failures_lock_the_account(app):
    from config import settings

    victim = signed_in_client(app)
    c = TestClient(app)
    for _ in range(settings.login_max_failures):
        c.post("/api/auth/login", json={"email": victim.email, "password": "guess-guess-1"})
    # Even the right password is refused while locked.
    r = c.post("/api/auth/login", json={"email": victim.email, "password": PASSWORD})
    assert r.status_code == 429


def test_password_reset_revokes_old_sessions(app):
    user = signed_in_client(app)
    c = TestClient(app)
    assert c.post("/api/auth/forgot-password", json={"email": user.email}).status_code == 200
    token = last_link_token(user.email)
    r = c.post("/api/auth/reset-password", json={"token": token, "password": "a-brand-new-pass-7"})
    assert r.status_code == 200
    # The session that existed before the reset is gone.
    assert user.get("/api/auth/me").status_code == 401
    r = c.post("/api/auth/login", json={"email": user.email, "password": "a-brand-new-pass-7"})
    assert r.status_code == 200


def test_forgot_password_does_not_reveal_accounts(anon):
    r = anon.post("/api/auth/forgot-password", json={"email": unique_email("nobody")})
    assert r.status_code == 200 and "on its way" in r.json()["message"]


def test_csrf_token_required_for_cookie_writes(app):
    c = signed_in_client(app)
    token = c.headers.pop("X-CSRF-Token")
    r = c.post("/api/check", json={"prompt": "hello"})
    assert r.status_code == 403
    c.headers["X-CSRF-Token"] = "forged"
    assert c.post("/api/check", json={"prompt": "hello"}).status_code == 403
    c.headers["X-CSRF-Token"] = token
    assert c.post("/api/check", json={"prompt": "hello"}).status_code == 200
    # Reads don't need it.
    c.headers.pop("X-CSRF-Token")
    assert c.get("/api/logs").status_code == 200


def test_session_cookie_is_httponly(anon):
    email = unique_email()
    anon.post("/api/auth/signup", json={"email": email, "password": PASSWORD, "org_name": "Cookie Co"})
    r = anon.post("/api/auth/verify-email", json={"token": last_link_token(email)})
    cookies = r.headers.get_list("set-cookie")
    session = next(h for h in cookies if h.startswith("rtg_session="))
    assert "HttpOnly" in session and "SameSite=lax" in session
    csrf = next(h for h in cookies if h.startswith("rtg_csrf="))
    assert "HttpOnly" not in csrf  # the page's script must be able to read it


def test_unauthenticated_requests_rejected(anon):
    assert anon.post("/api/check", json={"prompt": "hi"}).status_code == 401
    assert anon.get("/api/logs").status_code == 401
    assert anon.get("/api/metrics").status_code == 401


def test_change_password_signs_out_other_devices(app):
    laptop = signed_in_client(app)
    phone = TestClient(app)
    r = phone.post("/api/auth/login", json={"email": laptop.email, "password": PASSWORD})
    phone.headers["X-CSRF-Token"] = r.json()["csrf_token"]

    r = laptop.post("/api/auth/change-password",
                    json={"current_password": PASSWORD, "new_password": "rotated-password-42"})
    assert r.status_code == 200
    assert laptop.get("/api/auth/me").status_code == 200
    assert phone.get("/api/auth/me").status_code == 401


def test_auth_rate_limiter_blocks_bursts():
    from security import RateLimiter

    lim = RateLimiter(3)
    assert all(lim.check("1.2.3.4")[0] for _ in range(3))
    assert lim.check("1.2.3.4")[0] is False
    assert lim.check("5.6.7.8")[0] is True
