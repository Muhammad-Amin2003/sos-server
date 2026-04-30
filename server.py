# server.py - Flask сервер для приема SOS сигналов
from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import logging

app = Flask(__name__)
CORS(app)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============ ХРАНИЛИЩЕ В ПАМЯТИ ============

alerts_database = []
users_database  = []

SECRET_KEY = 'sos20_secret_key'


# ============ ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ============

def generate_token(user_id, role):
    payload = {
        'user_id': user_id,
        'role':    role,
        'exp':     datetime.utcnow() + timedelta(days=30)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')


def verify_token(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


def get_current_user():
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return None
    payload = verify_token(auth_header[7:])
    if not payload:
        return None
    return next((u for u in users_database if u['id'] == payload['user_id']), None)


# ============ AUTH ENDPOINTS ============

@app.route('/api/auth/register', methods=['POST'])
def register():
    """Регистрация нового пользователя"""
    try:
        data        = request.get_json()
        name        = data.get('name', '').strip()
        email       = data.get('email', '').strip().lower()
        password    = data.get('password', '')
        role        = data.get('role', 'user')
        phone       = data.get('phone', '')
        blood_type  = data.get('blood_type', '')
        allergies   = data.get('allergies', '')
        medications = data.get('medications', '')

        if not name or not email or not password:
            return jsonify({'status': 'error', 'message': 'Заполните все поля'}), 400

        if any(u['email'] == email for u in users_database):
            return jsonify({'status': 'error', 'message': 'Email уже зарегистрирован'}), 409

        user = {
            'id':          len(users_database) + 1,
            'name':        name,
            'email':       email,
            'password':    generate_password_hash(password),
            'role':        role,
            'phone':       phone,
            'blood_type':  blood_type,
            'allergies':   allergies,
            'medications': medications,
            'created_at':  datetime.now().isoformat()
        }
        users_database.append(user)

        token = generate_token(user['id'], user['role'])
        logger.info(f"✅ Новый пользователь: {name} ({email}) роль={role}")

        return jsonify({
            'status':  'success',
            'token':   token,
            'role':    user['role'],
            'user_id': str(user['id']),
            'name':    user['name']
        }), 201

    except Exception as e:
        logger.error(f"❌ Ошибка регистрации: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/auth/login', methods=['POST'])
def login():
    """Вход пользователя"""
    try:
        data     = request.get_json()
        email    = data.get('email', '').strip().lower()
        password = data.get('password', '')

        user = next((u for u in users_database if u['email'] == email), None)

        if not user or not check_password_hash(user['password'], password):
            return jsonify({'status': 'error', 'message': 'Неверный email или пароль'}), 401

        token = generate_token(user['id'], user['role'])
        logger.info(f"🔑 Вход: {user['name']} ({email})")

        return jsonify({
            'status':  'success',
            'token':   token,
            'role':    user['role'],
            'user_id': str(user['id']),
            'name':    user['name']
        })

    except Exception as e:
        logger.error(f"❌ Ошибка входа: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/auth/profile', methods=['GET'])
def get_profile():
    """Получить профиль текущего пользователя"""
    user = get_current_user()
    if not user:
        return jsonify({'status': 'error', 'message': 'Не авторизован'}), 401
    return jsonify({
        'status':      'success',
        'id':          user['id'],
        'name':        user['name'],
        'email':       user['email'],
        'phone':       user.get('phone', ''),
        'blood_type':  user.get('blood_type', ''),
        'allergies':   user.get('allergies', ''),
        'medications': user.get('medications', ''),
        'role':        user['role']
    })


@app.route('/api/auth/profile', methods=['PUT'])
def update_profile():
    """Обновить профиль пользователя"""
    user = get_current_user()
    if not user:
        return jsonify({'status': 'error', 'message': 'Не авторизован'}), 401

    try:
        data = request.get_json()
        user['name']        = data.get('name',        user['name'])
        user['phone']       = data.get('phone',       user.get('phone', ''))
        user['blood_type']  = data.get('blood_type',  user.get('blood_type', ''))
        user['allergies']   = data.get('allergies',   user.get('allergies', ''))
        user['medications'] = data.get('medications', user.get('medications', ''))

        logger.info(f"✏️ Профиль обновлён: {user['name']}")

        return jsonify({
            'status':      'success',
            'id':          user['id'],
            'name':        user['name'],
            'email':       user['email'],
            'phone':       user.get('phone', ''),
            'blood_type':  user.get('blood_type', ''),
            'allergies':   user.get('allergies', ''),
            'medications': user.get('medications', ''),
            'role':        user['role']
        })

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ============ SOS ENDPOINTS ============

@app.route('/api/emergency', methods=['POST'])
def receive_emergency_alert():
    """Получить сигнал бедствия"""
    try:
        data = request.get_json()

        if not data:
            return jsonify({'status': 'error', 'message': 'Пустой JSON'}), 400

        required_fields = ['name', 'phone', 'latitude', 'longitude']
        for field in required_fields:
            if field not in data:
                return jsonify({'status': 'error', 'message': f'Отсутствует поле: {field}'}), 400

        alert = {
            'id':          len(alerts_database) + 1,
            'timestamp':   datetime.now().isoformat(),
            'name':        data.get('name'),
            'phone':       data.get('phone'),
            'blood_type':  data.get('blood_type', 'Неизвестно'),
            'allergies':   data.get('allergies', ''),
            'medications': data.get('medications', ''),
            'latitude':    data.get('latitude'),
            'longitude':   data.get('longitude'),
            'accuracy':    data.get('accuracy'),
            'device_name': data.get('device_name'),
            'os_version':  data.get('os_version'),
            'status':      'received'
        }

        alerts_database.append(alert)

        logger.info(f"🚨 НОВЫЙ СИГНАЛ SOS: {alert['name']} ({alert['phone']})")
        logger.info(f"📍 Локация: {alert['latitude']}, {alert['longitude']}")
        logger.info(f"⏰ Время: {alert['timestamp']}")

        return jsonify({
            'status':    'success',
            'message':   'Сигнал получен',
            'alert_id':  alert['id'],
            'timestamp': alert['timestamp']
        }), 201

    except Exception as e:
        logger.error(f"❌ Ошибка: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/emergency/list', methods=['GET'])
def get_alerts():
    """Получить все сигналы"""
    return jsonify({
        'status': 'success',
        'count':  len(alerts_database),
        'alerts': alerts_database
    }), 200


@app.route('/api/emergency/<int:alert_id>', methods=['GET'])
def get_alert(alert_id):
    """Получить конкретный сигнал"""
    for alert in alerts_database:
        if alert['id'] == alert_id:
            return jsonify({'status': 'success', 'alert': alert}), 200
    return jsonify({'status': 'error', 'message': 'Сигнал не найден'}), 404


@app.route('/api/emergency/<int:alert_id>/status', methods=['PUT'])
def update_alert_status(alert_id):
    """Обновить статус сигнала"""
    try:
        data = request.get_json()
        for alert in alerts_database:
            if alert['id'] == alert_id:
                alert['status'] = data.get('status', 'received')
                logger.info(f"✅ Статус обновлен: {alert_id} → {alert['status']}")
                return jsonify({'status': 'success', 'alert': alert}), 200
        return jsonify({'status': 'error', 'message': 'Сигнал не найден'}), 404

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/health', methods=['GET'])
def health_check():
    """Проверка здоровья сервера"""
    return jsonify({
        'status':    'ok',
        'message':   'Сервер работает',
        'users':     len(users_database),
        'alerts':    len(alerts_database),
        'timestamp': datetime.now().isoformat()
    }), 200


# ============ ERROR HANDLERS ============

@app.errorhandler(404)
def not_found(error):
    return jsonify({'status': 'error', 'message': 'Маршрут не найден'}), 404


@app.errorhandler(500)
def server_error(error):
    return jsonify({'status': 'error', 'message': 'Ошибка сервера'}), 500


# ============ ЗАПУСК ============

if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("🚨 СЕРВЕР ПРИЕМА SOS СИГНАЛОВ")
    print("=" * 60)
    print("📡 Сервер запущен на http://127.0.0.1:8080")
    print("📝 API документация:")
    print("   POST   /api/auth/register          - регистрация")
    print("   POST   /api/auth/login             - вход")
    print("   GET    /api/auth/profile           - профиль")
    print("   PUT    /api/auth/profile           - обновить профиль")
    print("   POST   /api/emergency              - получить сигнал")
    print("   GET    /api/emergency/list         - список всех сигналов")
    print("   GET    /api/emergency/<id>         - получить сигнал по ID")
    print("   PUT    /api/emergency/<id>/status  - обновить статус")
    print("   GET    /api/health                 - проверка здоровья")
    print("=" * 60 + "\n")

    app.run(
        host='0.0.0.0',
        port=8080,
        debug=True,
        threaded=True
    )