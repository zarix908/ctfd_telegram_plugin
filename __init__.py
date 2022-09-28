import hashlib
import hmac

from flask import request, render_template, session, url_for
from werkzeug.routing import Rule
from werkzeug.utils import redirect

from CTFd.cache import clear_standings
from CTFd.models import db, Users
from CTFd.schemas.users import UserSchema
from CTFd.utils import validators
from CTFd.utils.crypto import verify_password
from CTFd.utils.decorators import admins_only
from CTFd.utils.email import user_created_notification
from CTFd.utils.logging import log
from CTFd.utils.security.auth import login_user


class TelegramUser(db.Model):
    __tablename__ = 'telegram_users'

    telegram_id = db.Column(db.String(20), primary_key=True)
    ctfd_id = db.Column(db.Integer)
    ctfd_password = db.Column(db.String)

    def __init__(self, telegram_id, ctfd_id):
        self.telegram_id = telegram_id
        self.ctfd_id = ctfd_id


def load(app):
    app.db.create_all()

    @app.route('/telegram/register', methods=['POST'])
    @admins_only
    def register():
        tg_id = request.json['telegram_id']
        reg_data = request.json['reg_data']

        resp, code = add_user(reg_data)
        if not resp['success']:
            return resp, code

        user = TelegramUser(tg_id, resp['data']['id'])
        app.db.session.add(user)
        app.db.session.commit()

        return resp

    app.view_functions['auth.admin_login'] = app.view_functions['auth.login']
    app.url_map.add(
        Rule(
            '/7666b3f5-6cff-4190-bec1-9f40794a73ba/login',
            endpoint='auth.admin_login',
            methods=['GET', 'POST']
        )
    )

    def login_handler():
        if not check_sign():
            return {'success': False, 'errors': ['security validation failed']}, 400

        telegram_user_id = request.args.get('id')
        telegram_user: TelegramUser = TelegramUser.query.get(telegram_id=telegram_user_id)
        if not telegram_user:
            return {'success': False, 'errors': ['telegram user not found']}, 400

        ctfd_user: Users = Users.query.get(id=telegram_user.ctfd_id)

        return login(ctfd_user.name, telegram_user.ctfd_password)

    app.view_functions['auth.login'] = login_handler
    app.url_map.add(Rule('/login', endpoint='auth.login', methods=['GET']))


def check_sign():
    """
    Check sign of query params.
    Note: https://core.telegram.org/widgets/login#checking-authorization.
    """
    args = request.args.to_dict()

    expected_hmac = args['hash']
    del args['hash']

    secret = bytes(bytearray.fromhex('e4503d9ba40ded746a6da38bc0e40776fb717b8290da24a15dd3ff4a07313c45'))
    data_check_string = '\n'.join(f'{k}={args[k]}' for k in sorted(args.keys()))
    calculated_hmac = hmac.new(secret, data_check_string, hashlib.sha256)

    return hmac.compare_digest(expected_hmac, calculated_hmac)


def add_user(req):
    """
    CTFd core code for user registration: api/v1/users.py (POST /api/v1/users)
    """
    schema = UserSchema("admin")
    response = schema.load(req)

    if response.errors:
        return {"success": False, "errors": response.errors}, 400

    db.session.add(response.data)
    db.session.commit()

    if request.args.get("notify"):
        name = response.data.name
        email = response.data.email
        password = req.get("password")

        user_created_notification(addr=email, name=name, password=password)

    clear_standings()

    response = schema.dump(response.data)

    return {"success": True, "data": response.data}, 200


def login(username, password):
    """
    CTFd core code for user login: auth.py (POST /login)
    """
    errors = []

    user = Users.query.filter_by(name=username).first()

    if user:
        if user.password is None:
            errors.append(
                "Your account was registered with a 3rd party authentication provider. "
                "Please try logging in with a configured authentication provider."
            )
            return render_template("login.html", errors=errors)

        if user and verify_password(password, user.password):
            session.regenerate()

            login_user(user)
            log("logins", "[{date}] {ip} - {name} logged in", name=user.name)

            db.session.close()
            if request.args.get("next") and validators.is_safe_url(
                    request.args.get("next")
            ):
                return redirect(request.args.get("next"))
            return redirect(url_for("challenges.listing"))

        else:
            # This user exists but the password is wrong
            log(
                "logins",
                "[{date}] {ip} - submitted invalid password for {name}",
                name=user.name,
            )
            errors.append("Your username or password is incorrect")
            db.session.close()
            return {'success': False, 'errors': errors}, 400
            # return render_template("login.html", errors=errors)
    else:
        # This user just doesn't exist
        log("logins", "[{date}] {ip} - submitted invalid account information")
        errors.append("Your username or password is incorrect")
        db.session.close()
        return {'success': False, 'errors': errors}, 400
        # return render_template("login.html", errors=errors)
