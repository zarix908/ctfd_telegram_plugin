from flask import request

from CTFd.cache import clear_standings
from CTFd.models import db
from CTFd.schemas.users import UserSchema
from CTFd.utils.decorators import admins_only
from CTFd.utils.email import user_created_notification


class TelegramUser(db.Model):
    __tablename__ = 'telegram_users'

    telegram_id = db.Column(db.String(20), primary_key=True)
    ctfd_id = db.Column(db.Integer)

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
