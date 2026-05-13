from flask import Flask, request, jsonify, render_template_string, redirect, session
from flask_cors import CORS
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import logging
import os
import psycopg2
from psycopg2.extras import RealDictCursor
import firebase_admin
from firebase_admin import credentials, messaging

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'admin_secret_key')
CORS(app)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SECRET_KEY = os.environ.get('SECRET_KEY', 'dev_fallback_change_in_production')

# Пароль для входа в админ-панель
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'sos_admin_2024')

_firebase_initialized = False
try:
    cred_path = os.environ.get('FIREBASE_CREDENTIALS', 'firebase-adminsdk.json')
    if os.path.exists(cred_path):
        cred = credentials.Certificate(cred_path)
        firebase_admin.initialize_app(cred)
        _firebase_initialized = True
        logger.info("✅ Firebase Admin SDK инициализирован")
    else:
        logger.warning("⚠️ firebase-adminsdk.json не найден — FCM отключён")
except Exception as e:
    logger.error(f"❌ Ошибка инициализации Firebase: {e}")


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
        fcm_token TEXT,
        created_at TEXT
    )''')
    try:
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS fcm_token TEXT")
    except Exception:
        pass
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
    except Exception:
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


def send_fcm_to_worker(worker_id, alert_id, alert_data):
    if not _firebase_initialized:
        logger.warning("FCM не инициализирован — push не отправлен")
        return False
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute('SELECT fcm_token FROM users WHERE id=%s', (worker_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row or not row.get('fcm_token'):
        return False
    try:
        message = messaging.Message(
            notification=messaging.Notification(
                title=f"🚨 Новый SOS сигнал #{alert_id}",
                body=f"{alert_data.get('name')} · {alert_data.get('service_type', 'Экстренный')}",
            ),
            data={
                'alert_id': str(alert_id),
                'name': str(alert_data.get('name', '')),
                'phone': str(alert_data.get('phone', '')),
                'blood_type': str(alert_data.get('blood_type', '')),
                'latitude': str(alert_data.get('latitude', '')),
                'longitude': str(alert_data.get('longitude', '')),
                'service_type': str(alert_data.get('service_type', '')),
            },
            android=messaging.AndroidConfig(
                priority='high',
                notification=messaging.AndroidNotification(
                    sound='default',
                    channel_id='sos_alerts',
                )
            ),
            token=row['fcm_token'],
        )
        response = messaging.send(message)
        logger.info(f"✅ FCM отправлен сотруднику #{worker_id}: {response}")
        return True
    except Exception as e:
        logger.error(f"❌ Ошибка FCM: {e}")
        return False


# ============================================================
# ADMIN PANEL HTML
# ============================================================

ADMIN_HTML = '''
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOS Admin Panel</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, sans-serif;
         background: #1a1a2e; color: #eee; min-height: 100vh; }
  .header { background: linear-gradient(135deg, #e53935, #c62828);
             padding: 20px 30px; display: flex; align-items: center;
             justify-content: space-between; }
  .header h1 { color: white; font-size: 22px; }
  .header a { color: #ffcdd2; text-decoration: none; font-size: 14px; }
  .container { max-width: 1100px; margin: 30px auto; padding: 0 20px; }
  .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 30px; }
  .stat-card { background: #16213e; border-radius: 12px; padding: 20px; text-align: center; }
  .stat-card .num { font-size: 36px; font-weight: bold; color: #e53935; }
  .stat-card .label { color: #aaa; margin-top: 4px; font-size: 14px; }
  .section { background: #16213e; border-radius: 12px; padding: 24px; margin-bottom: 24px; }
  .section h2 { margin-bottom: 16px; font-size: 18px; color: #ff6b6b; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; padding: 10px 12px; background: #0f3460;
       color: #aaa; font-size: 13px; }
  td { padding: 12px; border-bottom: 1px solid #0f3460; font-size: 14px; }
  tr:hover td { background: #0f3460; }
  .badge { padding: 4px 10px; border-radius: 20px; font-size: 12px;
           font-weight: bold; display: inline-block; }
  .badge-user { background: #1e3a5f; color: #64b5f6; }
  .badge-worker { background: #1b5e20; color: #81c784; }
  .btn { padding: 6px 14px; border: none; border-radius: 8px;
         cursor: pointer; font-size: 13px; font-weight: bold; }
  .btn-promote { background: #2e7d32; color: white; }
  .btn-demote  { background: #b71c1c; color: white; }
  .btn-delete  { background: #424242; color: #ef9a9a; margin-left: 4px; }
  .btn-primary { background: #e53935; color: white; padding: 10px 24px;
                 font-size: 15px; border-radius: 10px; width: 100%; margin-top: 8px; }
  .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  input, select { width: 100%; padding: 10px 14px; background: #0f3460;
                  border: 1px solid #1e3a5f; border-radius: 8px;
                  color: white; font-size: 14px; margin-bottom: 12px; }
  input::placeholder { color: #666; }
  .login-box { max-width: 380px; margin: 100px auto; background: #16213e;
               border-radius: 16px; padding: 40px; text-align: center; }
  .login-box h1 { color: #e53935; margin-bottom: 24px; }
  .alert { background: #b71c1c; color: white; padding: 10px 16px;
           border-radius: 8px; margin-bottom: 16px; font-size: 14px; }
  .available-yes { color: #81c784; }
  .available-no  { color: #ef9a9a; }
</style>
</head>
<body>

{% if not logged_in %}
<!-- СТРАНИЦА ВХОДА -->
<div class="login-box">
  <h1>🚨 SOS Admin</h1>
  {% if error %}<div class="alert">{{ error }}</div>{% endif %}
  <form method="POST" action="/admin/login">
    <input type="password" name="password" placeholder="Пароль администратора">
    <button class="btn btn-primary" type="submit">Войти</button>
  </form>
</div>

{% else %}
<!-- ПАНЕЛЬ УПРАВЛЕНИЯ -->
<div class="header">
  <h1>🚨 SOS Admin Panel</h1>
  <a href="/admin/logout">Выйти</a>
</div>

<div class="container">

  <!-- Статистика -->
  <div class="stats">
    <div class="stat-card">
      <div class="num">{{ stats.total_users }}</div>
      <div class="label">Всего пользователей</div>
    </div>
    <div class="stat-card">
      <div class="num">{{ stats.workers }}</div>
      <div class="label">Сотрудников</div>
    </div>
    <div class="stat-card">
      <div class="num">{{ stats.free_workers }}</div>
      <div class="label">Свободных сотрудников</div>
    </div>
  </div>

  <!-- Создать сотрудника -->
  <div class="section">
    <h2>➕ Создать аккаунт сотрудника</h2>
    {% if create_error %}<div class="alert">{{ create_error }}</div>{% endif %}
    {% if create_success %}<div class="alert" style="background:#2e7d32">{{ create_success }}</div>{% endif %}
    <form method="POST" action="/admin/create-worker">
      <div class="form-row">
        <input type="text" name="name" placeholder="Имя" required>
        <input type="text" name="phone" placeholder="Телефон" required>
      </div>
      <div class="form-row">
        <input type="email" name="email" placeholder="Email" required>
        <input type="password" name="password" placeholder="Пароль (мин. 6 символов)" required>
      </div>
      <input type="text" name="position" placeholder="Должность (например: Врач скорой помощи)">
      <button class="btn btn-primary" type="submit">Создать сотрудника</button>
    </form>
  </div>

  <!-- Список пользователей -->
  <div class="section">
    <h2>👥 Все пользователи</h2>
    <table>
      <thead>
        <tr>
          <th>#</th>
          <th>Имя</th>
          <th>Email</th>
          <th>Телефон</th>
          <th>Роль</th>
          <th>Доступен</th>
          <th>Дата</th>
          <th>Действия</th>
        </tr>
      </thead>
      <tbody>
        {% for u in users %}
        <tr>
          <td>{{ u.id }}</td>
          <td>{{ u.name }}</td>
          <td>{{ u.email }}</td>
          <td>{{ u.phone or '—' }}</td>
          <td>
            {% if u.role == 'worker' %}
              <span class="badge badge-worker">👷 Сотрудник</span>
            {% else %}
              <span class="badge badge-user">👤 Пользователь</span>
            {% endif %}
          </td>
          <td>
            {% if u.role == 'worker' %}
              {% if u.is_available %}
                <span class="available-yes">🟢 Да</span>
              {% else %}
                <span class="available-no">🔴 Нет</span>
              {% endif %}
            {% else %}—{% endif %}
          </td>
          <td>{{ u.created_at[:10] if u.created_at else '—' }}</td>
          <td>
            {% if u.role == 'user' %}
              <form method="POST" action="/admin/set-role" style="display:inline">
                <input type="hidden" name="user_id" value="{{ u.id }}">
                <input type="hidden" name="role" value="worker">
                <button class="btn btn-promote" type="submit">↑ Сотрудник</button>
              </form>
            {% else %}
              <form method="POST" action="/admin/set-role" style="display:inline">
                <input type="hidden" name="user_id" value="{{ u.id }}">
                <input type="hidden" name="role" value="user">
                <button class="btn btn-demote" type="submit">↓ Пользователь</button>
              </form>
            {% endif %}
            <form method="POST" action="/admin/delete-user" style="display:inline"
                  onsubmit="return confirm('Удалить пользователя?')">
              <input type="hidden" name="user_id" value="{{ u.id }}">
              <button class="btn btn-delete" type="submit">✕</button>
            </form>
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  <!-- Последние SOS сигналы -->
  <div class="section">
    <h2>🚨 Последние SOS сигналы</h2>
    <table>
      <thead>
        <tr>
          <th>#</th>
          <th>Имя</th>
          <th>Телефон</th>
          <th>Служба</th>
          <th>Статус</th>
          <th>Сотрудник</th>
          <th>Время</th>
        </tr>
      </thead>
      <tbody>
        {% for a in alerts %}
        <tr>
          <td>{{ a.id }}</td>
          <td>{{ a.name }}</td>
          <td>{{ a.phone }}</td>
          <td>{{ a.service_type or '—' }}</td>
          <td>
            {% if a.status == 'received' %}<span style="color:#ef9a9a">🔴 Новый</span>
            {% elif a.status == 'assigned' %}<span style="color:#ffcc02">🟡 Принят</span>
            {% elif a.status == 'completed' %}<span style="color:#81c784">🟢 Завершён</span>
            {% else %}{{ a.status }}{% endif %}
          </td>
          <td>{{ a.assigned_worker_name or '—' }}</td>
          <td>{{ a.timestamp[:16] if a.timestamp else '—' }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

</div>
{% endif %}
</body>
</html>
'''


# ============================================================
# ADMIN ROUTES
# ============================================================

@app.route('/admin')
def admin_panel():
    logged_in = session.get('admin_logged_in', False)
    if not logged_in:
        return render_template_string(ADMIN_HTML, logged_in=False, error=None)

    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute('SELECT * FROM users ORDER BY id DESC')
    users = [dict(r) for r in cur.fetchall()]

    cur.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT 20')
    alerts = [dict(r) for r in cur.fetchall()]

    cur.execute('SELECT COUNT(*) FROM users')
    total_users = cur.fetchone()['count']
    cur.execute("SELECT COUNT(*) FROM users WHERE role='worker'")
    workers = cur.fetchone()['count']
    cur.execute("SELECT COUNT(*) FROM users WHERE role='worker' AND is_available=TRUE")
    free_workers = cur.fetchone()['count']

    cur.close(); conn.close()

    stats = {'total_users': total_users, 'workers': workers, 'free_workers': free_workers}
    return render_template_string(ADMIN_HTML, logged_in=True, users=users,
                                  alerts=alerts, stats=stats,
                                  create_error=None, create_success=None)


@app.route('/admin/login', methods=['POST'])
def admin_login():
    password = request.form.get('password', '')
    if password == ADMIN_PASSWORD:
        session['admin_logged_in'] = True
        return redirect('/admin')
    return render_template_string(ADMIN_HTML, logged_in=False,
                                  error='Неверный пароль')


@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect('/admin')


@app.route('/admin/set-role', methods=['POST'])
def admin_set_role():
    if not session.get('admin_logged_in'):
        return redirect('/admin')
    user_id = request.form.get('user_id')
    role    = request.form.get('role')
    if role not in ('user', 'worker'):
        return redirect('/admin')
    conn = get_db()
    cur = conn.cursor()
    cur.execute('UPDATE users SET role=%s WHERE id=%s', (role, user_id))
    conn.commit(); cur.close(); conn.close()
    logger.info(f"✅ Роль пользователя #{user_id} изменена на {role}")
    return redirect('/admin')


@app.route('/admin/create-worker', methods=['POST'])
def admin_create_worker():
    if not session.get('admin_logged_in'):
        return redirect('/admin')

    name     = request.form.get('name', '').strip()
    phone    = request.form.get('phone', '').strip()
    email    = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')
    position = request.form.get('position', '').strip()

    def show_error(msg):
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute('SELECT * FROM users ORDER BY id DESC')
        users = [dict(r) for r in cur.fetchall()]
        cur.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT 20')
        alerts = [dict(r) for r in cur.fetchall()]
        cur.execute('SELECT COUNT(*) FROM users'); total = cur.fetchone()['count']
        cur.execute("SELECT COUNT(*) FROM users WHERE role='worker'"); w = cur.fetchone()['count']
        cur.execute("SELECT COUNT(*) FROM users WHERE role='worker' AND is_available=TRUE"); fw = cur.fetchone()['count']
        cur.close(); conn.close()
        stats = {'total_users': total, 'workers': w, 'free_workers': fw}
        return render_template_string(ADMIN_HTML, logged_in=True, users=users,
                                      alerts=alerts, stats=stats,
                                      create_error=msg, create_success=None)

    if not name or not phone or not email or not password:
        return show_error('Заполните все обязательные поля')
    if len(password) < 6:
        return show_error('Пароль должен быть не менее 6 символов')

    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute('SELECT id FROM users WHERE email=%s', (email,))
        if cur.fetchone():
            cur.close(); conn.close()
            return show_error('Пользователь с таким email уже существует')

        cur.execute('''INSERT INTO users
            (name, email, password, role, phone, blood_type,
             allergies, medications, is_available, created_at)
            VALUES (%s,%s,%s,'worker',%s,'','','',TRUE,%s)''',
            (name, email, generate_password_hash(password),
             phone, datetime.now().isoformat()))
        conn.commit(); cur.close(); conn.close()
        logger.info(f"✅ Создан сотрудник: {name} ({email})")

        # Показываем успех
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute('SELECT * FROM users ORDER BY id DESC')
        users = [dict(r) for r in cur.fetchall()]
        cur.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT 20')
        alerts = [dict(r) for r in cur.fetchall()]
        cur.execute('SELECT COUNT(*) FROM users'); total = cur.fetchone()['count']
        cur.execute("SELECT COUNT(*) FROM users WHERE role='worker'"); w = cur.fetchone()['count']
        cur.execute("SELECT COUNT(*) FROM users WHERE role='worker' AND is_available=TRUE"); fw = cur.fetchone()['count']
        cur.close(); conn.close()
        stats = {'total_users': total, 'workers': w, 'free_workers': fw}
        return render_template_string(ADMIN_HTML, logged_in=True, users=users,
                                      alerts=alerts, stats=stats,
                                      create_error=None,
                                      create_success=f'✅ Сотрудник {name} создан! Email: {email}')
    except Exception as e:
        return show_error(f'Ошибка: {str(e)}')


@app.route('/admin/delete-user', methods=['POST'])
def admin_delete_user():
    if not session.get('admin_logged_in'):
        return redirect('/admin')
    user_id = request.form.get('user_id')
    conn = get_db()
    cur = conn.cursor()
    # Сначала убираем ссылки в alerts
    cur.execute('UPDATE alerts SET assigned_worker_id=NULL WHERE assigned_worker_id=%s', (user_id,))
    cur.execute('DELETE FROM users WHERE id=%s', (user_id,))
    conn.commit(); cur.close(); conn.close()
    logger.info(f"🗑 Пользователь #{user_id} удалён")
    return redirect('/admin')


# ============================================================
# EXISTING API ROUTES (unchanged)
# ============================================================

@app.route('/api/auth/phone', methods=['POST'])
def phone_auth():
    """
    Telegram-style phone auth.
    Принимает номер телефона + firebase_uid (уже верифицированный Firebase).
    Если пользователь существует → вход, если нет → автоматическая регистрация.
    """
    try:
        data         = request.get_json()
        phone        = data.get('phone', '').strip()
        firebase_uid = data.get('firebase_uid', '').strip()

        if not phone or not firebase_uid:
            return jsonify({'status': 'error', 'message': 'phone и firebase_uid обязательны'}), 400

        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Ищем пользователя по телефону
        cur.execute('SELECT * FROM users WHERE phone=%s', (phone,))
        user = cur.fetchone()

        if user:
            # Пользователь найден → вход
            user = dict(user)
            cur.close(); conn.close()
            token = generate_token(user['id'], user['role'])
            logger.info(f"🔑 Phone login: {phone} роль={user['role']}")
            return jsonify({
                'status': 'success',
                'token': token,
                'role': user['role'],
                'user_id': str(user['id']),
                'name': user.get('name', ''),
                'is_new': False
            })
        else:
            # Новый пользователь → автоматическая регистрация как user
            cur.execute('''INSERT INTO users
                (name, email, password, role, phone, blood_type,
                 allergies, medications, is_available, created_at)
                VALUES (%s,%s,%s,%s,%s,'','','',TRUE,%s) RETURNING *''',
                ('', '', generate_password_hash(firebase_uid),
                 'user', phone, datetime.now().isoformat()))
            new_user = dict(cur.fetchone())
            conn.commit(); cur.close(); conn.close()

            token = generate_token(new_user['id'], new_user['role'])
            logger.info(f"✅ Phone register: {phone}")
            return jsonify({
                'status': 'success',
                'token': token,
                'role': new_user['role'],
                'user_id': str(new_user['id']),
                'name': '',
                'is_new': True
            }), 201

    except Exception as e:
        logger.error(f"❌ Phone auth error: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        name        = data.get('name', '').strip()
        email       = data.get('email', '').strip().lower()
        password    = data.get('password', '')
        # Роль всегда "user" — сотрудников создаёт только администратор
        role        = 'user'
        phone       = data.get('phone', '')
        blood_type  = data.get('blood_type', '')
        allergies   = data.get('allergies', '')
        medications = data.get('medications', '')
        fcm_token   = data.get('fcm_token', '')

        if not name or not email or not password:
            return jsonify({'status': 'error', 'message': 'Заполните все поля'}), 400

        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute('SELECT id FROM users WHERE email=%s', (email,))
        if cur.fetchone():
            cur.close(); conn.close()
            return jsonify({'status': 'error', 'message': 'Email уже зарегистрирован'}), 409

        cur.execute('''INSERT INTO users
            (name, email, password, role, phone, blood_type, allergies,
             medications, is_available, fcm_token, created_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *''',
            (name, email, generate_password_hash(password), role, phone,
             blood_type, allergies, medications, True,
             fcm_token, datetime.now().isoformat()))
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
        data      = request.get_json()
        email     = data.get('email', '').strip().lower()
        password  = data.get('password', '')
        fcm_token = data.get('fcm_token', '')

        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute('SELECT * FROM users WHERE email=%s', (email,))
        user = cur.fetchone()

        if not user or not check_password_hash(user['password'], password):
            cur.close(); conn.close()
            return jsonify({'status': 'error', 'message': 'Неверный email или пароль'}), 401

        user = dict(user)
        if fcm_token:
            cur.execute('UPDATE users SET fcm_token=%s WHERE id=%s',
                        (fcm_token, user['id']))
            conn.commit()
        cur.close(); conn.close()

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


@app.route('/api/auth/fcm-token', methods=['PUT'])
def update_fcm_token():
    user = get_current_user()
    if not user:
        return jsonify({'status': 'error', 'message': 'Не авторизован'}), 401
    data = request.get_json()
    fcm_token = data.get('fcm_token', '').strip()
    if not fcm_token:
        return jsonify({'status': 'error', 'message': 'fcm_token обязателен'}), 400
    conn = get_db()
    cur = conn.cursor()
    cur.execute('UPDATE users SET fcm_token=%s WHERE id=%s', (fcm_token, user['id']))
    conn.commit(); cur.close(); conn.close()
    return jsonify({'status': 'success'})


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
        return jsonify({'status': 'success', 'is_available': is_available})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/worker/availability', methods=['GET'])
def get_my_availability():
    user = get_current_user()
    if not user:
        return jsonify({'status': 'error', 'message': 'Не авторизован'}), 401
    return jsonify({'status': 'success', 'is_available': user.get('is_available', True)})


@app.route('/api/admin/reset-workers', methods=['POST'])
def reset_all_workers():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET is_available=TRUE WHERE role='worker'")
    conn.commit()
    cur.execute("SELECT COUNT(*) FROM users WHERE role='worker'")
    count = cur.fetchone()[0]
    cur.close(); conn.close()
    return jsonify({'status': 'success', 'workers_reset': count})


def assign_free_worker(alert_id, service_type, alert_data):
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
        conn.commit()
        send_fcm_to_worker(worker['id'], alert_id, alert_data)
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
                return jsonify({'status': 'error', 'message': f'Отсутствует поле: {field}'}), 400

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

        worker = assign_free_worker(alert_id, data.get('service_type', ''), data)
        response_data = {
            'status': 'success',
            'alert_id': alert_id,
            'timestamp': datetime.now().isoformat()
        }
        if worker:
            response_data['assigned_worker'] = {'name': worker['name'], 'phone': worker['phone']}
            response_data['message'] = f"Сигнал получен. Назначен: {worker['name']}"
        else:
            response_data['message'] = 'Сигнал получен. Свободных сотрудников нет.'
        return jsonify(response_data), 201
    except Exception as e:
        logger.error(f"❌ Ошибка SOS: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/emergency/list', methods=['GET'])
def get_alerts():
    user = get_current_user()
    if not user or user['role'] not in ('worker', 'admin'):
        return jsonify({'status': 'error', 'message': 'Нет доступа'}), 403
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute('SELECT * FROM alerts ORDER BY id DESC')
    alerts = [dict(r) for r in cur.fetchall()]
    cur.close(); conn.close()
    return jsonify(alerts)


@app.route('/api/emergency/my', methods=['GET'])
def get_my_alerts():
    user = get_current_user()
    if not user:
        return jsonify({'status': 'error', 'message': 'Не авторизован'}), 401
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute('''SELECT id, timestamp, service_type, service_number,
                          status, assigned_worker_name, latitude, longitude
                   FROM alerts WHERE phone=%s
                   ORDER BY id DESC LIMIT 50''',
                (user.get('phone'),))
    alerts = [dict(r) for r in cur.fetchall()]
    cur.close(); conn.close()
    return jsonify({'status': 'success', 'alerts': alerts})


@app.route('/api/emergency/<int:alert_id>', methods=['GET'])
def get_alert(alert_id):
    user = get_current_user()
    if not user:
        return jsonify({'status': 'error', 'message': 'Не авторизован'}), 401
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
    user = get_current_user()
    if not user or user['role'] != 'worker':
        return jsonify({'status': 'error', 'message': 'Только для сотрудников'}), 403
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
        conn.commit(); cur.close(); conn.close()
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


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
        'firebase_enabled': _firebase_initialized,
        'timestamp': datetime.now().isoformat()
    })


@app.errorhandler(404)
def not_found(e):
    return jsonify({'status': 'error', 'message': 'Не найден'}), 404


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
