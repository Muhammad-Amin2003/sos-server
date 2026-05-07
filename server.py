from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import logging
import os
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)
CORS(app)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SECRET_KEY = 'sos20_secret_key'

def get_db():
    return psycopg2.connect(os.environ['DATABASE_URL'], sslmode='require')

def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute('''CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name TEXT,
        email TEXT UNIQUE,
        password TEXT,
        role TEXT,
        phone TEXT,
        blood_type TEXT,
        allergies TEXT,
        medications TEXT,
        is_available BOOLEAN DEFAULT TRUE,
        created_at TEXT
    )''')

    cur.execute('''CREATE TABLE IF NOT EXISTS alerts (
        id SERIAL PRIMARY KEY,
        timestamp TEXT,
        name TEXT,
        phone TEXT,
        blood_type TEXT,
        allergies TEXT,
        medications TEXT,
        latitude REAL,
        longitude REAL,
        accuracy REAL,
        device_name TEXT,
        os_version TEXT,
        service_type TEXT,
        service_number TEXT,
        status TEXT DEFAULT 'received',
        assigned_worker_id INTEGER REFERENCES users(id),
        assigned_worker_name TEXT,
        assigned_at TEXT
    )''')

    conn.commit()
    cur.close()
    conn.close()

init_db()

def generate_token(user_id, role):
    payload = {
        'user_id': user_id,
        'role': role,
        'exp': datetime.utcnow() + timedelta(days=30)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def verify_token(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    except:
        return None

def get_current_user():
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return None
    payload = verify_token(auth_header[7:])
    if not payload:
        return None
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute('SELECT * FROM users WHERE id=%s', (payload['user_id'],))
    user = cur.fetchone()
    cur.close()
    conn.close()
    return dict(user) if user else None

# ─────────────────────────────────────────
# AUTH
# ─────────────────────────────────────────

@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
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

        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute('SELECT id FROM users WHERE email=%s', (email,))
        if cur.fetchone():
            cur.close(); conn.close()
            return jsonify({'status': 'error', 'message': 'Email уже зарегистрирован'}), 409

        cur.execute('''INSERT INTO users
            (name, email, password, role, phone, blood_type, allergies, medications, is_available, created_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *''',
            (name, email, generate_password_hash(password), role, phone,
             blood_type, allergies, medications, True, datetime.now().isoformat()))
        user = dict(cur.fetchone())
        conn.commit(); cur.close(); conn.close()

        token = generate_token(user['id'], user['role'])
        logger.info(f"✅ Новый пользователь: {name} ({email}) роль={role}")
        return jsonify({
            'status': 'success',
            'token': token,
            'role': user['role'],
            'user_id': str(user['id']),
            'name': user['name']
        }), 201

    except Exception as e:
        logger.error(f"❌ Ошибка регистрации: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data     = request.get_json()
        email    = data.get('email', '').strip().lower()
        password = data.get('password', '')

        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute('SELECT * FROM users WHERE email=%s', (email,))
        user = cur.fetchone()
        cur.close(); conn.close()

        if not user or not check_password_hash(user['password'], password):
            return jsonify({'status': 'error', 'message': 'Неверный email или пароль'}), 401

        user = dict(user)
        token = generate_token(user['id'], user['role'])
        logger.info(f"🔑 Вход: {user['name']} ({email})")
        return jsonify({
            'status': 'success',
            'token': token,
            'role': user['role'],
            'user_id': str(user['id']),
            'name': user['name']
        })

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/auth/profile', methods=['GET'])
def get_profile():
    user = get_current_user()
    if not user:
        return jsonify({'status': 'error', 'message': 'Не авторизован'}), 401
    return jsonify({
        'status': 'success',
        'id': user['id'],
        'name': user['name'],
        'email': user['email'],
        'phone': user.get('phone', ''),
        'blood_type': user.get('blood_type', ''),
        'allergies': user.get('allergies', ''),
        'medications': user.get('medications', ''),
        'role': user['role'],
        'is_available': user.get('is_available', True)
    })

@app.route('/api/auth/profile', methods=['PUT'])
def update_profile():
    user = get_current_user()
    if not user:
        return jsonify({'status': 'error', 'message': 'Не авторизован'}), 401
    try:
        data = request.get_json()
        conn = get_db()
        cur = conn.cursor()
        cur.execute('''UPDATE users SET
            name=%s, phone=%s, blood_type=%s, allergies=%s, medications=%s
            WHERE id=%s''',
            (data.get('name', user['name']),
             data.get('phone', user.get('phone', '')),
             data.get('blood_type', user.get('blood_type', '')),
             data.get('allergies', user.get('allergies', '')),
             data.get('medications', user.get('medications', '')),
             user['id']))
        conn.commit(); cur.close(); conn.close()
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# ─────────────────────────────────────────
# СОТРУДНИКИ — статус доступности
# ─────────────────────────────────────────

@app.route('/api/worker/availability', methods=['PUT'])
def set_availability():
    user = get_current_user()
    if not user or user['role'] != 'worker':
        return jsonify({'status': 'error', 'message': 'Только для сотрудников'}), 403
    try:
        data = request.get_json()
        is_available = data.get('is_available', True)
        conn = get_db()
        cur = conn.cursor()
        cur.execute('UPDATE users SET is_available=%s WHERE id=%s',
                    (is_available, user['id']))
        conn.commit(); cur.close(); conn.close()
        status_text = "свободен" if is_available else "занят"
        logger.info(f"👷 {user['name']} теперь {status_text}")
        return jsonify({'status': 'success', 'is_available': is_available})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/worker/availability', methods=['GET'])
def get_my_availability():
    user = get_current_user()
    if not user:
        return jsonify({'status': 'error', 'message': 'Не авторизован'}), 401
    return jsonify({
        'status': 'success',
        'is_available': user.get('is_available', True)
    })

# ─────────────────────────────────────────
# ✅ НОВЫЙ ЭНДПОИНТ: сброс всех сотрудников в is_available=TRUE
# Используй если база "застряла" — все заняты навсегда
# POST /api/admin/reset-workers
# ─────────────────────────────────────────

@app.route('/api/admin/reset-workers', methods=['POST'])
def reset_all_workers():
    """Сбрасывает всех сотрудников в статус 'свободен'. Для отладки."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET is_available=TRUE WHERE role='worker'")
    conn.commit()
    cur.execute("SELECT COUNT(*) FROM users WHERE role='worker'")
    count = cur.fetchone()[0]
    cur.close(); conn.close()
    logger.info(f"🔄 Сброс: {count} сотрудников теперь свободны")
    return jsonify({'status': 'success', 'workers_reset': count})

# ─────────────────────────────────────────
# SOS СИГНАЛЫ
# ─────────────────────────────────────────

def assign_free_worker(alert_id, service_type):
    """
    Находит свободного сотрудника и назначает на SOS сигнал.

    ✅ ИСПРАВЛЕНО 1: убрана фильтрация по service_type в SQL —
       все сотрудники универсальные, назначаем любого свободного.

    ✅ ИСПРАВЛЕНО 2: сотрудник НЕ помечается is_available=FALSE автоматически.
       Теперь сотрудник сам управляет своей доступностью через
       PUT /api/worker/availability или завершая сигнал.
       Это решает проблему когда все сотрудники навсегда "застревали" в занятых.
    """
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute('''SELECT id, name, phone FROM users
                   WHERE role='worker' AND is_available=TRUE
                   ORDER BY RANDOM() LIMIT 1''')
    worker = cur.fetchone()

    if worker:
        worker = dict(worker)
        now = datetime.now().isoformat()

        cur.execute('''UPDATE alerts SET
                       assigned_worker_id=%s,
                       assigned_worker_name=%s,
                       assigned_at=%s,
                       status='assigned'
                       WHERE id=%s''',
                    (worker['id'], worker['name'], now, alert_id))

        # ✅ УБРАНО: cur.execute('UPDATE users SET is_available=FALSE WHERE id=%s', ...)
        # Сотрудник остаётся свободным — он сам меняет статус через приложение.
        # Это предотвращает бесконечную блокировку всех сотрудников.

        conn.commit()
        logger.info(f"👷 Сотрудник {worker['name']} назначен на сигнал #{alert_id}")
    else:
        logger.warning(f"⚠️ Нет свободных сотрудников для сигнала #{alert_id}")

    cur.close()
    conn.close()
    return worker


@app.route('/api/emergency', methods=['POST'])
def receive_emergency_alert():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'Пустой JSON'}), 400

        for field in ['name', 'phone', 'latitude', 'longitude']:
            if field not in data:
                return jsonify({'status': 'error',
                                'message': f'Отсутствует поле: {field}'}), 400

        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute('''INSERT INTO alerts
            (timestamp, name, phone, blood_type, allergies, medications,
             latitude, longitude, accuracy, device_name, os_version,
             service_type, service_number, status)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            RETURNING id''',
            (datetime.now().isoformat(),
             data.get('name'), data.get('phone'),
             data.get('blood_type', ''), data.get('allergies', ''),
             data.get('medications', ''),
             data.get('latitude'), data.get('longitude'),
             data.get('accuracy'), data.get('device_name'),
             data.get('os_version'), data.get('service_type', ''),
             data.get('service_number', ''), 'received'))

        alert_id = cur.fetchone()['id']
        conn.commit(); cur.close(); conn.close()

        logger.info(f"🚨 SOS #{alert_id}: {data.get('name')} ({data.get('phone')})")

        worker = assign_free_worker(alert_id, data.get('service_type', ''))

        response_data = {
            'status': 'success',
            'message': 'Сигнал получен',
            'alert_id': alert_id,
            'timestamp': datetime.now().isoformat()
        }

        if worker:
            response_data['assigned_worker'] = {
                'name': worker['name'],
                'phone': worker['phone']
            }
            response_data['message'] = f"Сигнал получен. Назначен сотрудник: {worker['name']}"
        else:
            response_data['message'] = 'Сигнал получен. Свободных сотрудников нет.'

        return jsonify(response_data), 201

    except Exception as e:
        logger.error(f"❌ Ошибка SOS: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/emergency/list', methods=['GET'])
def get_alerts():
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute('SELECT * FROM alerts ORDER BY id DESC')
    alerts = [dict(r) for r in cur.fetchall()]
    cur.close(); conn.close()
    return jsonify(alerts)

@app.route('/api/emergency/<int:alert_id>', methods=['GET'])
def get_alert(alert_id):
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute('SELECT * FROM alerts WHERE id=%s', (alert_id,))
    alert = cur.fetchone()
    cur.close(); conn.close()
    if alert:
        return jsonify({'status': 'success', 'alert': dict(alert)})
    return jsonify({'status': 'error', 'message': 'Не найден'}), 404

@app.route('/api/emergency/<int:alert_id>/status', methods=['PUT'])
def update_alert_status(alert_id):
    """Сотрудник завершает сигнал — становится снова свободным"""
    try:
        data = request.get_json()
        new_status = data.get('status', 'received')

        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute('UPDATE alerts SET status=%s WHERE id=%s RETURNING assigned_worker_id',
                    (new_status, alert_id))
        result = cur.fetchone()

        if new_status == 'completed' and result and result['assigned_worker_id']:
            cur.execute('UPDATE users SET is_available=TRUE WHERE id=%s',
                        (result['assigned_worker_id'],))
            logger.info(f"✅ Сотрудник #{result['assigned_worker_id']} снова свободен")

        conn.commit(); cur.close(); conn.close()
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# ─────────────────────────────────────────
# ЗДОРОВЬЕ СЕРВЕРА
# ─────────────────────────────────────────

@app.route('/api/health', methods=['GET'])
def health_check():
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT COUNT(*) FROM users')
    users = cur.fetchone()[0]
    cur.execute('SELECT COUNT(*) FROM alerts')
    alerts = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM users WHERE role='worker' AND is_available=TRUE")
    free_workers = cur.fetchone()[0]
    cur.close(); conn.close()
    return jsonify({
        'status': 'ok',
        'users': users,
        'alerts': alerts,
        'free_workers': free_workers,
        'timestamp': datetime.now().isoformat()
    })

@app.errorhandler(404)
def not_found(e):
    return jsonify({'status': 'error', 'message': 'Не найден'}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
