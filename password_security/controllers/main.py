# Copyright 2015 LasLabs Inc.
# License LGPL-3.0 or later (http://www.gnu.org/licenses/lgpl.html).

import logging

from werkzeug.exceptions import BadRequest

from odoo import http
from odoo.exceptions import UserError
from odoo.http import request

from odoo.addons.auth_signup.controllers.main import AuthSignupHome
from odoo.addons.web.controllers.home import ensure_db

_logger = logging.getLogger(__name__)


class PasswordSecurityHome(AuthSignupHome):
    def do_signup(self, qcontext):
        password = qcontext.get("password")
        user = request.env.user
        user._check_password(password)
        return super().do_signup(qcontext)

    @http.route()
    def web_login(self, *args, **kw):
        ensure_db()
        response = super().web_login(*args, **kw)
        if not request.params.get("login_success"):
            return response
        # Now, I'm an authenticated user
        if not request.env.user._password_has_expired():
            return response
        # My password is expired, kick me out
        request.env.user.action_expire_password()
        request.session.logout(keep_db=True)
        # I was kicked out, so set login_success in request params to False
        request.params["login_success"] = False
        redirect = request.env.user.partner_id.signup_url
        return request.redirect(redirect)

    @http.route()
    def web_auth_signup(self, *args, **kw):
        """Try to catch all the possible exceptions not already handled in the parent method"""

        try:
            qcontext = self.get_auth_signup_qcontext()
        except Exception:
            raise BadRequest from None  # HTTPError: 400 Client Error: BAD REQUEST

        try:
            return super().web_auth_signup(*args, **kw)
        except Exception as e:
            # Here we catch any generic exception since UserError is already
            # handled in parent method web_auth_signup()
            qcontext["error"] = str(e)
            response = request.render("auth_signup.signup", qcontext)
            response.headers["X-Frame-Options"] = "SAMEORIGIN"
            response.headers["Content-Security-Policy"] = "frame-ancestors 'self'"
            return response

    @http.route()
    def web_auth_reset_password(self, *args, **kw):
        """It provides hook to disallow front-facing resets inside of min
        Unfortuantely had to reimplement some core logic here because of
        nested logic in parent
        """
        qcontext = self.get_auth_signup_qcontext()
        if (
            request.httprequest.method == "POST"
            and qcontext.get("login")
            and "error" not in qcontext
            and not qcontext.get("token")
        ):
            login = qcontext.get("login")
            user = (
                request.env["res.users"]
                .sudo()
                .search(
                    [("login", "=", login)],
                    limit=1,
                )
            )
            if not user:
                user = (
                    request.env["res.users"]
                    .sudo()
                    .search(
                        [("email", "=", login)],
                        limit=1,
                    )
                )
            try:
                user._validate_pass_reset()
            except UserError as e:
                qcontext["error"] = e.args[0]
                response = request.render("auth_signup.reset_password", qcontext)
                response.headers["X-Frame-Options"] = "SAMEORIGIN"
                response.headers["Content-Security-Policy"] = "frame-ancestors 'self'"
                return response

        return super().web_auth_reset_password(*args, **kw)
