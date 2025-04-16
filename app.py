import eventlet
eventlet.monkey_patch()

import sqlite3
import uuid
import logging
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, make_response, jsonify, send_from_directory
from flask_socketio import SocketIO, send, emit, join_room, leave_room
from datetime import datetime, timedelta
import os
import json
from functools import wraps
import hashlib
import re
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import shutil
import time
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect

# 이미지 파일 확장자 설정
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'jfif', 'webp'}

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # 실제 운영 환경에서는 안전한 키로 변경해야 합니다
app.config['SESSION_COOKIE_NAME'] = 'market_session'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # HTTPS 환경에서만 쿠키 전송 (프로덕션에서는 True로 설정)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF 보호를 위한 SameSite 설정
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)  # 세션 만료 시간 설정
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 최대 업로드 크기 50MB
app.config['SESSION_TYPE'] = 'filesystem'  # 세션 저장소 설정
app.config['MAX_LOGIN_ATTEMPTS'] = 5  # 로그인 실패 횟수 제한
app.config['LOGIN_TIMEOUT'] = 300  # 로그인 제한 시간(초)
app.config['WTF_CSRF_ENABLED'] = True  # CSRF 보호 활성화

# CSRF 토큰을 헤더에서도 가져올 수 있도록 설정
app.config['WTF_CSRF_CHECK_DEFAULT'] = False
app.config['WTF_CSRF_HEADERS'] = ['X-CSRF-TOKEN']

# 데이터베이스 파일 경로 설정
DATABASE = 'market.db'

# bcrypt 및 CSRF 설정
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)

# 특정 경로에 대해 CSRF 보호 제외
csrf.exempt('/payment/create')
csrf.exempt('/payment/handle')
csrf.exempt('/notifications/mark-all-read')
csrf.exempt('/notifications/mark-read/<int:notification_id>')

# 로깅 설정 추가
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='app.log'
)
logger = logging.getLogger(__name__)

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# 통화 형식 필터 추가
def format_currency(value):
    """통화 형식으로 숫자를 포맷팅하는 필터"""
    if value is None:
        return '0'
    try:
        return "{:,}".format(float(value))
    except (ValueError, TypeError):
        return str(value)

# 날짜 형식 필터 추가
def datetime_format(value, format='%Y-%m-%d %H:%M:%S'):
    """날짜 형식을 포맷팅하는 필터"""
    if value is None:
        return ''
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            try:
                value = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
            except (ValueError, AttributeError):
                return value
    try:
        return value.strftime(format)
    except (ValueError, AttributeError):
        return str(value)

# Jinja 환경에 필터 등록
app.jinja_env.filters['format_currency'] = format_currency
app.jinja_env.filters['datetime'] = datetime_format

class User(UserMixin):
    def __init__(self, id, username, password=None, is_admin=False, is_suspended=False):
        self.id = id
        self.username = username
        self.password = password
        self.is_admin = is_admin
        self.is_suspended = is_suspended

    def get_id(self):
        return str(self.id)

@login_manager.user_loader
def load_user(user_id):
    """사용자 정보를 데이터베이스에서 로드하는 함수"""
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute('SELECT * FROM user WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if user:
            user_data = {
                'id': user['id'] if 'id' in user else None,
                'username': user['username'] if 'username' in user else None,
                'email': user['email'] if 'email' in user else None, 
                'password': user['password'] if 'password' in user else None,
                'created_at': user['created_at'] if 'created_at' in user else None,
                'is_admin': user['is_admin'] if 'is_admin' in user else False,
                'is_suspended': user['is_suspended'] if 'is_suspended' in user else False
            }
            return user_data
        return None
    except Exception as e:
        print(f"사용자 로드 중 오류 발생: {str(e)}")
        return None

# 로그인 필요 데코레이터
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('로그인이 필요합니다.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_db():
    """데이터베이스 연결을 가져오거나 새로 생성합니다."""
    if 'db' not in g:
        g.db = sqlite3.connect(
            DATABASE,
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row
        
        # SQLite 타입 어댑터 등록
        def adapt_datetime(dt):
            return dt.isoformat()
        
        def convert_datetime(s):
            try:
                return datetime.fromisoformat(s.decode())
            except:
                return None
        
        sqlite3.register_adapter(datetime, adapt_datetime)
        sqlite3.register_converter("timestamp", convert_datetime)
    
    return g.db

@app.teardown_appcontext
def close_connection(exception):
    """애플리케이션 컨텍스트가 종료될 때 데이터베이스 연결을 닫습니다."""
    db = g.pop('db', None)
    if db is not None:
        try:
            db.close()
        except Exception as e:
            print(f"데이터베이스 연결 종료 중 오류 발생: {e}")

def init_db():
    """데이터베이스를 초기화합니다."""
    db = get_db()
    with app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()

# 기본 라우트
@app.route('/')
def index():
    return render_template('index.html')

# 비밀번호 해싱 유틸리티 함수
def hash_password(password):
    """비밀번호를 해싱하는 함수 (bcrypt 사용)"""
    return bcrypt.generate_password_hash(password).decode('utf-8')

# 비밀번호 검증 유틸리티 함수
def verify_password(password, hashed_password):
    """비밀번호가 해시와 일치하는지 확인하는 함수 (bcrypt 사용)"""
    # 기존 SHA-256 방식 (이전 계정 호환성 지원)
    if len(hashed_password) == 64:  # SHA-256 해시 길이
        salt = app.config.get('SECRET_KEY', 'default-salt')
        return hashlib.sha256((password + salt).encode()).hexdigest() == hashed_password
    # bcrypt 방식
    return bcrypt.check_password_hash(hashed_password, password)

# 로그인 시도 제한 함수 추가
def check_login_attempts(username):
    """로그인 시도 횟수 확인 및 제한 함수"""
    current_time = datetime.now()
    if username in login_attempts:
        attempts, last_attempt_time = login_attempts[username]
        
        # 제한 시간이 지났으면 초기화
        if (current_time - last_attempt_time).total_seconds() > app.config['LOGIN_TIMEOUT']:
            login_attempts[username] = (1, current_time)
            return True
        
        # 최대 시도 횟수를 초과하면 제한
        if attempts >= app.config['MAX_LOGIN_ATTEMPTS']:
            return False
        
        # 시도 횟수 증가
        login_attempts[username] = (attempts + 1, current_time)
        return True
    else:
        login_attempts[username] = (1, current_time)
        return True

# 세션 갱신 미들웨어 추가
@app.before_request
def session_management():
    session.permanent = True
    # 마지막 활동 시간 갱신
    if 'user_id' in session:
        session['last_activity'] = datetime.now().isoformat()
    
    # 세션 만료 확인
    if 'last_activity' in session:
        last_activity = datetime.fromisoformat(session['last_activity'])
        if (datetime.now() - last_activity) > timedelta(hours=2):
            session.clear()
            flash('세션이 만료되었습니다. 다시 로그인해주세요.')
            return redirect(url_for('login'))

# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            flash('사용자명과 비밀번호를 모두 입력해주세요.')
            return redirect(url_for('login'))
            
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if user is None:
            flash('사용자를 찾을 수 없습니다.')
            return redirect(url_for('login'))
        
        user_id = user['id']
        hashed_password = user['password']
        
        if verify_password(password, hashed_password):
            session.clear()
            session['user_id'] = user_id
            session['username'] = username
            session['last_activity'] = datetime.now().isoformat()
            
            # is_admin 값을 명시적으로 가져와 불리언으로 변환하여 세션에 저장
            session['is_admin'] = bool(user['is_admin'])
            session['is_suspended'] = bool(user['is_suspended']) if 'is_suspended' in user else False
            
            print(f"로그인 성공: {username}, 관리자 권한: {session['is_admin']}")
            
            return redirect(url_for('dashboard'))
        else:
            flash('비밀번호가 일치하지 않습니다.')
            return redirect(url_for('login'))
    
    return render_template('login.html')

# 로그아웃
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# 세션 확인 미들웨어
@app.before_request
def check_session():
    # 로그인, 회원가입, 정적 파일 요청은 세션 확인 제외
    if request.endpoint in ['login', 'register', 'static', 'index'] or request.path.startswith('/static/'):
        return
    
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # 사용자 정보를 g 객체에 저장
    g.user_id = session['user_id']
    g.username = session['username']
    g.is_admin = session['is_admin']
    g.is_suspended = session['is_suspended']
    
    # 계정 정지 여부 확인
    if g.is_suspended:
        session.clear()
        flash('계정이 정지되었습니다. 관리자에게 문의하세요.')
        return redirect(url_for('login'))

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
@login_required
def dashboard():
    """대시보드 페이지"""
    # 세션 디버깅 정보 출력
    print(f"현재 세션 정보: user_id={session.get('user_id')}, username={session.get('username')}, is_admin={session.get('is_admin')}")
    
    db = None
    try:
        db = get_db()
        cursor = db.cursor()
        
        # 사용자 정보 조회
        cursor.execute('''
            SELECT id, username, email, created_at, is_admin 
            FROM user 
            WHERE id = ?
        ''', (session['user_id'],))
        user = cursor.fetchone()
        
        # 세션에 관리자 권한 정보 업데이트
        if user and 'is_admin' in user:
            session['is_admin'] = bool(user['is_admin'])
            print(f"데이터베이스에서 불러온 is_admin 값: {user['is_admin']}, 세션에 저장된 값: {session['is_admin']}")
        
        # 상품 목록 조회
        cursor.execute('''
            SELECT p.*, u.username as seller_name 
            FROM product p 
            JOIN user u ON p.seller_id = u.id 
            WHERE p.is_deleted = 0 
            ORDER BY p.created_at DESC 
            LIMIT 10
        ''')
        products = cursor.fetchall()
        
        # 전체 채팅 메시지 조회
        cursor.execute('''
            SELECT m.*, u.username as sender_name 
            FROM chat_message m 
            JOIN user u ON m.sender_id = u.id 
            WHERE m.room_id = 'global_chat' 
            ORDER BY m.created_at DESC 
            LIMIT 50
        ''')
        global_messages = cursor.fetchall()
        
        # 메시지의 시간 형식 처리
        formatted_messages = []
        for message in global_messages:
            message_dict = dict(message)
            if 'created_at' in message_dict and message_dict['created_at']:
                # datetime이 문자열이 아닌 경우 형식화
                if not isinstance(message_dict['created_at'], str):
                    try:
                        message_dict['created_at'] = message_dict['created_at'].strftime('%Y-%m-%d %H:%M:%S')
                    except (AttributeError, ValueError):
                        # 문자열로 변환한 후 마이크로초 제거
                        message_dict['created_at'] = str(message_dict['created_at']).split('.')[0]
            formatted_messages.append(message_dict)
        
        return render_template('dashboard.html', 
                            user=user,
                            products=products,
                            global_messages=formatted_messages)
    except Exception as e:
        print(f"대시보드 로드 중 오류 발생: {str(e)}")
        flash('대시보드를 불러오는 중 오류가 발생했습니다.')
        return redirect(url_for('index'))

# 프로필 페이지: bio 업데이트 가능
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    db = get_db()
    cursor = db.cursor()
    
    if request.method == 'POST':
        bio = request.form.get('bio', '')
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        update_fields = []
        update_values = []
        
        # 바이오 업데이트
        if bio:
            update_fields.append("bio = ?")
            update_values.append(bio)
        
        # 비밀번호 변경
        if current_password and new_password:
            if len(new_password) < 7:
                flash('새 비밀번호는 7자 이상이어야 합니다.')
                return redirect(url_for('profile'))
            if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{7,}$', new_password):
                flash('새 비밀번호는 영문, 숫자, 특수문자를 포함해야 합니다.')
                return redirect(url_for('profile'))
            if new_password != confirm_password:
                flash('새 비밀번호와 확인이 일치하지 않습니다.')
                return redirect(url_for('profile'))
            
            # 현재 비밀번호 확인
            cursor.execute("SELECT password FROM user WHERE id = ?", (session['user_id'],))
            user_password = cursor.fetchone()['password']
            
            if not verify_password(current_password, user_password):
                flash('현재 비밀번호가 올바르지 않습니다.')
                return redirect(url_for('profile'))
            
            # 새 비밀번호 해싱
            hashed_password = hash_password(new_password)
            update_fields.append("password = ?")
            update_values.append(hashed_password)
            flash('비밀번호가 성공적으로 변경되었습니다.')
        elif current_password or new_password or confirm_password:
            flash('비밀번호를 변경하려면 현재 비밀번호와 새 비밀번호를 모두 입력해야 합니다.')
            return redirect(url_for('profile'))
        
        if update_fields:
            update_fields.append("updated_at = datetime('now')")
            update_sql = f"UPDATE user SET {', '.join(update_fields)} WHERE id = ?"
            update_values.append(session['user_id'])
            cursor.execute(update_sql, update_values)
            db.commit()
            flash('프로필이 업데이트되었습니다.')
            
        return redirect(url_for('profile'))
    
    # 사용자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    
    # 사용자의 상품 목록 가져오기
    cursor.execute('''
        SELECT p.id, p.title, p.price, p.created_at, u.username as seller_name
        FROM product p
        JOIN user u ON p.seller_id = u.id
        WHERE p.seller_id = ? AND p.is_deleted = 0 AND p.id IS NOT NULL
        ORDER BY p.created_at DESC
    ''', (session['user_id'],))
    products = [dict(row) for row in cursor.fetchall()]
    
    # 디버깅을 위한 로그 추가
    app.logger.debug(f"조회된 상품 목록: {products}")
    app.logger.debug(f"상품 개수: {len(products)}")
    if products:
        app.logger.debug(f"첫 번째 상품의 ID: {products[0]['id']}")
    
    # 송금 내역
    cursor.execute("""
        SELECT p.*, 
               u1.username as sender_name,
               u2.username as receiver_name
        FROM payment p
        JOIN user u1 ON p.sender_id = u1.id
        JOIN user u2 ON p.receiver_id = u2.id
        WHERE p.sender_id = ? OR p.receiver_id = ?
        ORDER BY p.created_at DESC
    """, (session['user_id'], session['user_id']))
    payments = cursor.fetchall()
    
    # 신고 내역
    cursor.execute("""
        SELECT r.*, 
               CASE 
                   WHEN r.target_type = 'user' THEN u.username
                   WHEN r.target_type = 'product' THEN p.title
               END as target_name,
               r.target_type
        FROM report r
        LEFT JOIN user u ON r.target_id = u.id AND r.target_type = 'user'
        LEFT JOIN product p ON r.target_id = p.id AND r.target_type = 'product'
        WHERE r.reporter_id = ?
        ORDER BY r.created_at DESC
    """, (session['user_id'],))
    reports = cursor.fetchall()
    
    return render_template('profile.html', 
                         user=user, 
                         products=products, 
                         payments=payments, 
                         reports=reports)

# 이미지 파일 확장자 체크 함수
def allowed_file(filename):
    if not filename:
        return False
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def optimize_image(image_path, max_size=(800, 800), quality=85):
    from PIL import Image, ExifTags
    import os
    
    try:
        img = Image.open(image_path)
        
        # EXIF 정보에서 방향 정보 추출 및 이미지 회전 처리
        try:
            for orientation in ExifTags.TAGS.keys():
                if ExifTags.TAGS[orientation] == 'Orientation':
                    break
            
            exif = dict(img._getexif().items())
            
            if orientation in exif:
                if exif[orientation] == 2:
                    img = img.transpose(Image.FLIP_LEFT_RIGHT)
                elif exif[orientation] == 3:
                    img = img.transpose(Image.ROTATE_180)
                elif exif[orientation] == 4:
                    img = img.transpose(Image.FLIP_TOP_BOTTOM)
                elif exif[orientation] == 5:
                    img = img.transpose(Image.FLIP_LEFT_RIGHT).transpose(Image.ROTATE_90)
                elif exif[orientation] == 6:
                    img = img.transpose(Image.ROTATE_270)
                elif exif[orientation] == 7:
                    img = img.transpose(Image.FLIP_LEFT_RIGHT).transpose(Image.ROTATE_270)
                elif exif[orientation] == 8:
                    img = img.transpose(Image.ROTATE_90)
        except (AttributeError, KeyError, IndexError):
            # EXIF 정보가 없는 경우 무시
            pass
            
        try:
            # 최신 PIL 버전용
            img.thumbnail(max_size, Image.Resampling.LANCZOS)
        except AttributeError:
            # 이전 PIL 버전용
            img.thumbnail(max_size, Image.LANCZOS if hasattr(Image, 'LANCZOS') else Image.ANTIALIAS)
        
        # 이미지 최적화
        if img.mode in ('RGBA', 'LA'):
            background = Image.new('RGB', img.size, (255, 255, 255))
            background.paste(img, mask=img.split()[-1])
            img = background
        
        # 이미지 저장
        img.save(image_path, 'JPEG', quality=quality, optimize=True)
        return True
    except Exception as e:
        print(f"이미지 최적화 중 오류 발생: {e}")
        return False

def validate_image_file(file):
    """이미지 파일 검증 함수"""
    if not file or not file.filename:
        return False, '이미지 파일을 선택해주세요.'
    
    if not allowed_file(file.filename):
        return False, '이미지는 JPG, JPEG, PNG, GIF 형식만 가능합니다.'
    
    # 파일 크기 검증 - 10MB로 제한
    if file.content_length > 10 * 1024 * 1024:
        return False, '이미지 크기는 10MB를 초과할 수 없습니다.'
    
    try:
        from PIL import Image
        # 파일 포인터를 처음으로 되돌림
        file.seek(0)
        img = Image.open(file)
        # 이미지가 실제로 로드 가능한지 확인
        img.verify()
        # 파일 포인터를 다시 처음으로 되돌림
        file.seek(0)
        return True, None
    except Exception as e:
        print(f"이미지 검증 오류: {e}")
        return False, f'이미지 파일이 손상되었거나 올바르지 않습니다: {str(e)}'

def save_image(file):
    """이미지 파일 저장 함수"""
    try:
        # 파일 포인터를 처음으로 되돌림
        file.seek(0)
        file_ext = os.path.splitext(file.filename)[1].lower()
        unique_filename = f"{uuid.uuid4()}{file_ext}"
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        # 업로드 폴더가 없으면 생성
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        # 이미지 저장
        file.save(image_path)
        
        # 이미지 최적화
        if optimize_image(image_path):
            return unique_filename
        else:
            # 최적화 실패 시 원본 파일 삭제
            os.remove(image_path)
            return None
    except Exception as e:
        print(f"이미지 저장 오류: {e}")
        return None

# 상품 등록
@app.route('/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    if request.method == 'POST':
        title = sanitize_input(request.form.get('title', '').strip())
        price = request.form.get('price', '').strip()
        description = sanitize_input(request.form.get('description', '').strip())
        
        # 필수 필드 검증
        if not title or not price or not description:
            flash('모든 필드를 입력해주세요.')
            return redirect(url_for('add_product'))
            
        # 제목 길이 제한
        if len(title) > 100:
            flash('제목은 100자 이내로 입력해주세요.')
            return redirect(url_for('add_product'))
        
        try:
            price = float(price)
            if price <= 0:
                flash('가격은 0보다 커야 합니다.')
                return redirect(url_for('add_product'))
            if price > 1000000000:  # 10억원 제한
                flash('가격이 너무 높습니다.')
                return redirect(url_for('add_product'))
        except ValueError:
            flash('유효한 가격을 입력해주세요.')
            return redirect(url_for('add_product'))
        
        # 이미지 업로드 처리
        image_urls = []
        
        # request.files 디버깅
        print(f"요청에 포함된 파일들: {list(request.files.keys())}")
        
        # 'images' 키로 파일 목록 가져오기
        uploaded_files = request.files.getlist('images')
        print(f"업로드된 파일 수: {len(uploaded_files)}")
        
        for file in uploaded_files:
            if file and file.filename:
                print(f"업로드 시도: {file.filename}")  # 디버깅
                try:
                    # 파일 확장자 확인
                    if not allowed_file(file.filename):
                        print(f"허용되지 않는 파일 형식: {file.filename}")
                        flash(f'허용되지 않는 파일 형식입니다: {file.filename}')
                        continue
                    
                    # 이미지 처리 함수 호출
                    filename, error = process_image_upload(file)
                    
                    if filename:
                        image_urls.append(filename)
                    elif error:
                        flash(error)
                except Exception as e:
                    print(f"예외 발생: {str(e)}")  # 디버깅
                    flash(f'이미지 처리 중 오류가 발생했습니다: {str(e)}')
        
        if len(image_urls) == 0:
            print("업로드된 이미지가 없습니다")
            flash('최소한 한 개의 이미지를 업로드해야 합니다.')
            return redirect(url_for('add_product'))
        
        try:
            db = get_db()
            cursor = db.cursor()
            
            # UUID를 사용하여 product_id 생성
            product_id = str(uuid.uuid4())
            
            # 이미지가 있는 경우 첫 번째 이미지를 메인 이미지로 설정
            main_image = image_urls[0] if image_urls else None
            
            cursor.execute('''
                INSERT INTO product (id, title, price, description, seller_id, image_url) 
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (product_id, title, price, description, session['user_id'], main_image))
            
            # 추가 이미지가 있는 경우 저장
            for image_url in image_urls[1:]:
                cursor.execute('''
                    INSERT INTO product_images (product_id, image_url) 
                    VALUES (?, ?)
                ''', (product_id, image_url))
            
            db.commit()
            flash('상품이 등록되었습니다.')
            return redirect(url_for('view_product', product_id=product_id))
            
        except Exception as e:
            db.rollback()
            flash('상품 등록 중 오류가 발생했습니다.')
            print(f"상품 등록 오류: {str(e)}")
            return redirect(url_for('add_product'))
    
    return render_template('add_product.html')

# 상품 상세보기
@app.route('/view_product/<string:product_id>')
def view_product(product_id):
    try:
        db = get_db()
        cursor = db.cursor()
        
        # 상품 정보 조회
        cursor.execute('''
            SELECT p.*, u.username as seller_name, u.report_count as seller_report_count
            FROM product p 
            JOIN user u ON p.seller_id = u.id 
            WHERE p.id = ? AND p.is_deleted = 0
        ''', (product_id,))
        product = cursor.fetchone()
        
        if not product:
            flash('존재하지 않는 상품입니다.')
            return redirect(url_for('dashboard'))
        
        # 상품에 대한 신고 횟수 조회
        cursor.execute('''
            SELECT COUNT(*) as report_count 
            FROM report 
            WHERE target_type = 'product' AND target_id = ?
        ''', (product_id,))
        product_report = cursor.fetchone()
        product_report_count = product_report['report_count'] if product_report else 0
        
        # 추가 이미지 조회
        cursor.execute('''
            SELECT image_url FROM product_images 
            WHERE product_id = ? 
            ORDER BY created_at
        ''', (product_id,))
        images = [row['image_url'] for row in cursor.fetchall()]
        
        return render_template('view_product.html', 
                            product=product,
                            images=images,
                            product_report_count=product_report_count)
    except Exception as e:
        print(f"상품 조회 중 오류 발생: {str(e)}")
        flash('상품을 불러오는 중 오류가 발생했습니다.')
        return redirect(url_for('dashboard'))

# 상품 수정
@app.route('/edit_product/<string:product_id>', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    db = get_db()
    cursor = db.cursor()
    
    # 제품 정보 조회
    cursor.execute("""
        SELECT p.*, GROUP_CONCAT(pi.image_url) as image_urls
        FROM product p
        LEFT JOIN product_images pi ON p.id = pi.product_id
        WHERE p.id = ?
        GROUP BY p.id
    """, (product_id,))
    product = cursor.fetchone()
    
    if not product:
        flash('존재하지 않는 제품입니다.')
        return redirect(url_for('dashboard'))
    
    # 현재 사용자가 판매자인지 확인
    if product['seller_id'] != session['user_id']:
        flash('자신의 제품만 수정할 수 있습니다.')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        title = request.form['title']
        price = request.form['price']
        description = request.form['description']
        
        # 필수 필드 검증
        if not title or not price or not description:
            flash('모든 필드를 입력해주세요.')
            return redirect(url_for('edit_product', product_id=product_id))
        
        try:
            price = float(price)
            if price <= 0:
                flash('가격은 0보다 커야 합니다.')
                return redirect(url_for('edit_product', product_id=product_id))
        except ValueError:
            flash('유효한 가격을 입력해주세요.')
            return redirect(url_for('edit_product', product_id=product_id))
        
        try:
            # 제품 정보 업데이트
            cursor.execute("""
                UPDATE product 
                SET title = ?, price = ?, description = ?, updated_at = datetime('now')
                WHERE id = ?
            """, (title, price, description, product_id))
            
            # 새로운 이미지 업로드 처리
            new_images = request.files.getlist('images')
            for file in new_images:
                if file and file.filename:
                    filename, error = process_image_upload(file)
                    if filename:
                        cursor.execute("""
                            INSERT INTO product_images (product_id, image_url) 
                            VALUES (?, ?)
                        """, (product_id, filename))
                    elif error:
                        flash(error)
            
            # 삭제할 이미지 처리
            delete_images = request.form.getlist('delete_images')
            if delete_images:
                for image_url in delete_images:
                    # 파일 시스템에서 이미지 삭제
                    image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_url)
                    if os.path.exists(image_path):
                        os.remove(image_path)
                    
                    # 데이터베이스에서 이미지 레코드 삭제
                    cursor.execute("DELETE FROM product_images WHERE product_id = ? AND image_url = ?", 
                                 (product_id, image_url))
            
            db.commit()
            flash('제품이 성공적으로 수정되었습니다.')
            return redirect(url_for('view_product', product_id=product_id))
            
        except Exception as e:
            db.rollback()
            flash('제품 수정 중 오류가 발생했습니다.')
            print(f"Error updating product: {e}")
            return redirect(url_for('edit_product', product_id=product_id))
    
    # GET 요청 처리
    images = []
    if product['image_urls']:
        images = product['image_urls'].split(',')
    
    return render_template('edit_product.html', product=product, images=images)

# 상품 삭제
@app.route('/delete_product/<string:product_id>', methods=['POST'])
@login_required
def delete_product(product_id):
    db = get_db()
    cursor = db.cursor()
    
    # 제품 정보 조회
    cursor.execute("SELECT seller_id FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    
    if not product:
        flash('존재하지 않는 제품입니다.')
        return redirect(url_for('dashboard'))
    
    # 현재 사용자가 판매자인지 확인
    if product['seller_id'] != session['user_id']:
        flash('자신의 제품만 삭제할 수 있습니다.')
        return redirect(url_for('dashboard'))
    
    try:
        # 제품 이미지 삭제
        cursor.execute("SELECT image_url FROM product_images WHERE product_id = ?", (product_id,))
        images = cursor.fetchall()
        
        for image in images:
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image['image_url'])
            if os.path.exists(image_path):
                os.remove(image_path)
        
        # 제품 이미지 레코드 삭제
        cursor.execute("DELETE FROM product_images WHERE product_id = ?", (product_id,))
        
        # 제품 삭제
        cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
        db.commit()
        
        flash('제품이 삭제되었습니다.')
    except Exception as e:
        db.rollback()
        flash('제품 삭제 중 오류가 발생했습니다.')
        print(f"Error deleting product: {e}")
    
    return redirect(url_for('dashboard'))

# 채팅방 생성 또는 찾기 함수
def get_or_create_chat_room(user1_id, user2_id, product_id=None):
    """
    두 사용자 간의 채팅방을 가져오거나 생성합니다.
    product_id가 제공되면 해당 상품에 대한 채팅방을 생성합니다.
    """
    db = get_db()
    cursor = db.cursor()
    
    try:
        # product_id가 있는 경우 해당 상품에 대한 채팅방 조회
        if product_id:
            cursor.execute('''
                SELECT cr.id FROM chat_room cr
                JOIN chat_participant cp1 ON cr.id = cp1.room_id
                JOIN chat_participant cp2 ON cr.id = cp2.room_id
                WHERE cp1.user_id = ? AND cp2.user_id = ? AND cr.product_id = ?
                AND cp1.user_id != cp2.user_id
            ''', (user1_id, user2_id, product_id))
        else:
            # 기존 방식대로 사용자 간 채팅방 조회 (product_id가 NULL인 경우)
            cursor.execute('''
                SELECT cr.id FROM chat_room cr
                JOIN chat_participant cp1 ON cr.id = cp1.room_id
                JOIN chat_participant cp2 ON cr.id = cp2.room_id
                WHERE cp1.user_id = ? AND cp2.user_id = ? AND cr.product_id IS NULL
                AND cp1.user_id != cp2.user_id
            ''', (user1_id, user2_id))
        
        chat_room = cursor.fetchone()
        
        if chat_room:
            return chat_room['id']
        
        # 채팅방이 없는 경우 새로 생성
        room_id = str(uuid.uuid4())
        cursor.execute('''
            INSERT INTO chat_room (id, created_at, product_id)
            VALUES (?, datetime('now'), ?)
        ''', (room_id, product_id))
        
        # 참여자 추가
        cursor.execute('''
            INSERT INTO chat_participant (room_id, user_id, joined_at)
            VALUES (?, ?, datetime('now'))
        ''', (room_id, user1_id))
        
        cursor.execute('''
            INSERT INTO chat_participant (room_id, user_id, joined_at)
            VALUES (?, ?, datetime('now'))
        ''', (room_id, user2_id))
        
        db.commit()
        return room_id
    except Exception as e:
        print(f"채팅방 생성 중 오류 발생: {str(e)}")
        db.rollback()
        return None

# 상품 검색
@app.route('/search')
@login_required
def search():
    keyword = request.args.get('keyword', '')
    db = get_db()
    cursor = db.cursor()
    
    # 키워드로 상품 검색
    cursor.execute("""
        SELECT p.*, u.username as seller_name
        FROM product p
        JOIN user u ON p.seller_id = u.id
        WHERE (p.title LIKE ? OR p.description LIKE ?) AND p.is_deleted = 0
    """, (f'%{keyword}%', f'%{keyword}%'))
    products = cursor.fetchall()
    
    return render_template('search_results.html', products=products, keyword=keyword)

# 이미지 유효성 검사 및 저장 함수
def process_image_upload(file, max_size=10*1024*1024):
    """이미지 파일 검증 및 저장 통합 함수"""
    if not file or not file.filename:
        return None, '이미지 파일을 선택해주세요.'
    
    # 파일 확장자 검증
    if not allowed_file(file.filename):
        return None, '이미지는 JPG, JPEG, PNG, GIF 형식만 가능합니다.'
    
    try:
        # 파일 크기 검증 - 명시적으로 10MB 제한
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        
        if file_size > max_size:  # 10MB
            return None, '이미지 크기는 10MB를 초과할 수 없습니다.'
        
        # 파일 검증
        from PIL import Image, ExifTags
        try:
            img = Image.open(file)
            img.verify()
            file.seek(0)
        except Exception as e:
            print(f"이미지 검증 오류: {str(e)}")
            return None, f'이미지 파일이 손상되었거나, 올바른 이미지가 아닙니다: {str(e)}'
        
        # 파일 저장
        file_ext = os.path.splitext(file.filename)[1].lower()
        unique_filename = f"{uuid.uuid4()}{file_ext}"
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        # 업로드 폴더가 없으면 생성
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        # 이미지 저장
        file.save(image_path)
        
        # 이미지 저장 후 경로 출력 (디버깅용)
        print(f"이미지 저장 경로: {image_path}")
        
        # 이미지 최적화
        if optimize_image(image_path):
            return unique_filename, None
        else:
            # 최적화 실패 시 원본 파일 삭제
            if os.path.exists(image_path):
                os.remove(image_path)
            return None, '이미지 최적화 중 오류가 발생했습니다.'
            
    except Exception as e:
        print(f"이미지 처리 오류: {str(e)}")
        return None, f'이미지 파일 처리 중 오류가 발생했습니다: {str(e)}'

# 신고하기 (개선된 버전)
@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    if request.method == 'POST':
        target_id = request.form['target_id']
        reason = request.form['reason']
        target_type = request.form['target_type']  # 'user' 또는 'product'
        
        # 입력값 검증
        if not target_id or not reason or not target_type:
            flash('모든 필드를 입력해주세요.')
            return redirect(url_for('report'))
            
        if target_type not in ['user', 'product']:
            flash('유효하지 않은 대상 유형입니다.')
            return redirect(url_for('report'))
        
        db = get_db()
        cursor = db.cursor()
        
        # 대상 존재 여부 확인
        if target_type == 'user':
            cursor.execute("SELECT id FROM user WHERE id = ?", (target_id,))
            if not cursor.fetchone():
                flash('존재하지 않는 사용자입니다.')
                return redirect(url_for('report'))
        else:  # product
            cursor.execute("SELECT id FROM product WHERE id = ? AND is_deleted = 0", (target_id,))
            if not cursor.fetchone():
                flash('존재하지 않는 상품입니다.')
                return redirect(url_for('report'))
        
        # 신고 내역 저장
        report_id = str(uuid.uuid4())
        cursor.execute("""
            INSERT INTO report (id, reporter_id, target_id, target_type, reason)
            VALUES (?, ?, ?, ?, ?)
        """, (report_id, session['user_id'], target_id, target_type, reason))
        
        # 신고 횟수 증가
        if target_type == 'user':
            cursor.execute("""
                UPDATE user 
                SET report_count = report_count + 1
                WHERE id = ?
            """, (target_id,))
            
            # 5회 이상 신고된 사용자 자동 정지
            cursor.execute("""
                UPDATE user 
                SET is_suspended = 1
                WHERE id = ? AND report_count >= 5
            """, (target_id,))
        else:  # product
            # 상품 삭제 기능은 일단 비활성화
            pass
        
        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))
    
    target_id = request.args.get('target_id')
    target_type = request.args.get('target_type')
    return render_template('report.html', target_id=target_id, target_type=target_type)

# 관리자 페이지
@app.route('/admin')
@login_required
def admin_dashboard():
    if not session.get('is_admin'):
        flash('관리자 권한이 필요합니다.')
        return redirect(url_for('dashboard'))
    
    db = get_db()
    cursor = db.cursor()
    
    # 사용자 목록 조회
    cursor.execute("""
        SELECT id, username, created_at, is_admin, is_suspended
        FROM user
        ORDER BY created_at DESC
    """)
    users = cursor.fetchall()
    
    # 상품 목록 조회
    cursor.execute("""
        SELECT p.*, u.username as seller_name
        FROM product p
        JOIN user u ON p.seller_id = u.id
        ORDER BY p.created_at DESC
    """)
    products = cursor.fetchall()
    
    # 신고 내역 조회
    cursor.execute("""
        SELECT r.*, 
               ru.username as reporter_name,
               CASE 
                   WHEN r.target_type = 'user' THEN tu.username
                   WHEN r.target_type = 'product' THEN tp.title
               END as target_name
        FROM report r
        JOIN user ru ON r.reporter_id = ru.id
        LEFT JOIN user tu ON r.target_type = 'user' AND r.target_id = tu.id
        LEFT JOIN product tp ON r.target_type = 'product' AND r.target_id = tp.id
        ORDER BY r.created_at DESC
    """)
    reports = cursor.fetchall()
    
    # 채팅방 목록 조회
    cursor.execute("""
        SELECT cr.id, cr.created_at, cr.is_active, cr.product_id
        FROM chat_room cr
        ORDER BY cr.created_at DESC
    """)
    chat_rooms = []
    for room in cursor.fetchall():
        room_dict = dict(room)
        
        # 채팅방 참여자 정보 조회
        cursor.execute("""
            SELECT u.id, u.username
            FROM chat_participant cp
            JOIN user u ON cp.user_id = u.id
            WHERE cp.room_id = ?
        """, (room['id'],))
        participants = cursor.fetchall()
        
        # 채팅방의 마지막 메시지 조회
        cursor.execute("""
            SELECT cm.content, cm.created_at, u.username
            FROM chat_message cm
            JOIN user u ON cm.sender_id = u.id
            WHERE cm.room_id = ?
            ORDER BY cm.created_at DESC
            LIMIT 1
        """, (room['id'],))
        last_message = cursor.fetchone()
        
        room_dict['participants'] = participants
        room_dict['last_message'] = last_message
        
        chat_rooms.append(room_dict)
    
    return render_template('admin_dashboard.html', 
                         users=users,
                         products=products,
                         reports=reports,
                         chat_rooms=chat_rooms)

# 사용자 계정 정지
@app.route('/admin/suspend_user/<user_id>', methods=['POST'])
@login_required
def suspend_user(user_id):
    if not session.get('is_admin'):
        flash('관리자만 접근할 수 있습니다.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    action = request.form.get('action')
    if action not in ['suspend', 'activate']:
        flash('잘못된 요청입니다.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    db = get_db()
    cursor = db.cursor()
    
    try:
        cursor.execute('SELECT * FROM user WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user:
            flash('사용자를 찾을 수 없습니다.', 'error')
            return redirect(url_for('admin_dashboard'))
        
        if user['is_admin']:
            flash('관리자는 정지할 수 없습니다.', 'error')
            return redirect(url_for('admin_dashboard'))
        
        cursor.execute('UPDATE user SET is_suspended = ? WHERE id = ?', 
                      (1 if action == 'suspend' else 0, user_id))
        db.commit()
        
        status = '정지' if action == 'suspend' else '활성화'
        flash(f'사용자 {user["username"]}이(가) {status}되었습니다.', 'success')
        
    except Exception as e:
        db.rollback()
        flash('오류가 발생했습니다.', 'error')
        print(f"Error in suspend_user: {str(e)}")
    
    return redirect(url_for('admin_dashboard'))

# 상품 삭제
@app.route('/admin/delete_product/<string:product_id>', methods=['POST'])
@login_required
def admin_delete_product(product_id):
    if not session.get('is_admin'):
        flash('관리자 권한이 필요합니다.')
        return redirect(url_for('dashboard'))
    
    db = get_db()
    cursor = db.cursor()
    
    try:
        # 제품 정보 확인
        cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
        product = cursor.fetchone()
        
        if not product:
            flash('존재하지 않는 제품입니다.')
            return redirect(url_for('admin_dashboard'))
        
        # 제품 이미지 삭제
        cursor.execute("SELECT image_url FROM product_images WHERE product_id = ?", (product_id,))
        images = cursor.fetchall()
        
        for image in images:
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image['image_url'])
            if os.path.exists(image_path):
                os.remove(image_path)
        
        # 제품 이미지 레코드 삭제
        cursor.execute("DELETE FROM product_images WHERE product_id = ?", (product_id,))
        
        # 제품 관련 데이터 삭제
        cursor.execute("DELETE FROM report WHERE target_type = 'product' AND target_id = ?", (product_id,))
        cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
        db.commit()
        
        flash('제품이 성공적으로 삭제되었습니다.')
    except Exception as e:
        db.rollback()
        flash('제품 삭제 중 오류가 발생했습니다.')
        app.logger.error(f'제품 삭제 오류: {str(e)}')
    
    return redirect(url_for('admin_dashboard'))

# 신고 처리
@app.route('/admin/handle_report/<string:report_id>', methods=['POST'])
@login_required
def handle_report(report_id):
    if not session.get('is_admin'):
        flash('관리자 권한이 필요합니다.')
        return redirect(url_for('dashboard'))
    
    status = request.form.get('status')
    if not status or status not in ['pending', 'resolved', 'rejected']:
        flash('유효하지 않은 상태입니다.')
        return redirect(url_for('admin_dashboard'))
    
    db = get_db()
    cursor = db.cursor()
    
    try:
        cursor.execute("UPDATE report SET status = ? WHERE id = ?", (status, report_id))
        db.commit()
        flash('신고 상태가 업데이트되었습니다.')
    except Exception as e:
        db.rollback()
        flash('신고 상태 업데이트 중 오류가 발생했습니다.')
        app.logger.error(f'신고 상태 업데이트 오류: {str(e)}')
    
    return redirect(url_for('admin_dashboard'))

# 채팅 내용 열람
@app.route('/admin/chat/<room_id>')
def view_chat(room_id):
    if 'user_id' not in session or not session['is_admin']:
        flash('관리자 권한이 필요합니다.')
        return redirect(url_for('dashboard'))
    
    db = get_db()
    cursor = db.cursor()
    
    # 채팅방 정보 조회
    cursor.execute("""
        SELECT * FROM chat_room WHERE id = ?
    """, (room_id,))
    room_info = cursor.fetchone()
    
    # 채팅방 참여자 정보 조회
    cursor.execute("""
        SELECT u.id, u.username, u.is_admin
        FROM chat_participant cp
        JOIN user u ON cp.user_id = u.id
        WHERE cp.room_id = ?
    """, (room_id,))
    participants = cursor.fetchall()
    
    # 관련 상품 정보 조회
    product = None
    if room_info and room_info['product_id']:
        cursor.execute("""
            SELECT p.*, u.username as seller_name
            FROM product p
            JOIN user u ON p.seller_id = u.id
            WHERE p.id = ?
        """, (room_info['product_id'],))
        product = cursor.fetchone()
    
    # 채팅 메시지 조회
    cursor.execute("""
        SELECT m.*, u.username as sender_name 
        FROM chat_message m 
        JOIN user u ON m.sender_id = u.id 
        WHERE m.room_id = ? 
        ORDER BY m.created_at
    """, (room_id,))
    messages = cursor.fetchall()
    
    return render_template('view_chat.html', 
                          messages=messages, 
                          room_info=room_info,
                          participants=participants,
                          product=product)

# 1:1 채팅방 생성 또는 조회
@app.route('/chat/<room_id>')
@login_required
def chat_room(room_id):
    db = None
    try:
        db = get_db()
        cursor = db.cursor()
        
        # 채팅방 존재 여부 및 제품 정보 확인
        cursor.execute('SELECT id, product_id FROM chat_room WHERE id = ?', (room_id,))
        room = cursor.fetchone()
        
        if not room:
            flash('존재하지 않는 채팅방입니다.', 'error')
            return redirect(url_for('dashboard'))
        
        # 채팅방 참여자 확인
        cursor.execute('''
            SELECT user_id FROM chat_participant 
            WHERE room_id = ? AND user_id = ?
        ''', (room_id, session['user_id']))
        participant = cursor.fetchone()
        
        if not participant:
            flash('채팅방에 참여할 권한이 없습니다.', 'error')
            return redirect(url_for('dashboard'))
        
        # 채팅방의 다른 참여자 정보 조회
        cursor.execute('''
            SELECT u.id, u.username, u.report_count
            FROM chat_participant p
            JOIN user u ON p.user_id = u.id
            WHERE p.room_id = ? AND p.user_id != ?
            LIMIT 1
        ''', (room_id, session['user_id']))
        other_user = cursor.fetchone()
        
        if not other_user:
            flash('채팅방의 상대방 정보를 찾을 수 없습니다.', 'error')
            return redirect(url_for('dashboard'))
        
        # 상대방의 온라인 상태 확인
        other_user = dict(other_user)
        other_user['is_online'] = False
        
        try:
            cursor.execute('''
                SELECT 1 FROM socketio_connection 
                WHERE user_id = ? AND last_activity > datetime('now', '-5 minutes')
                LIMIT 1
            ''', (other_user['id'],))
            
            if cursor.fetchone():
                other_user['is_online'] = True
        except Exception as e:
            print(f"온라인 상태 확인 중 오류 발생: {str(e)}")
        
        # 관련 상품 정보 조회
        product = None
        product_report_count = 0
        if room and room['product_id']:
            try:
                cursor.execute('''
                    SELECT id, title, price, description, seller_id 
                    FROM product 
                    WHERE id = ? AND is_deleted = 0
                ''', (room['product_id'],))
                product_data = cursor.fetchone()
                if product_data:
                    product = dict(product_data)
                    
                    # 상품 신고 횟수 확인
                    cursor.execute('''
                        SELECT COUNT(*) as report_count 
                        FROM report 
                        WHERE target_type = 'product' AND target_id = ?
                    ''', (room['product_id'],))
                    report_data = cursor.fetchone()
                    product_report_count = report_data['report_count'] if report_data else 0
            except Exception as e:
                print(f"채팅방 상품 정보 조회 중 오류 발생: {str(e)}")
        
        # 채팅 메시지 조회
        cursor.execute('''
            SELECT cm.*, u.username 
            FROM chat_message cm
            JOIN user u ON cm.sender_id = u.id
            WHERE cm.room_id = ?
            ORDER BY cm.created_at ASC
        ''', (room_id,))
        messages = []
        for message in cursor.fetchall():
            msg_dict = dict(message)
            if 'created_at' in msg_dict and msg_dict['created_at']:
                if isinstance(msg_dict['created_at'], str):
                    pass
                else:
                    msg_dict['created_at'] = msg_dict['created_at'].strftime('%Y-%m-%d %H:%M:%S')
            messages.append(msg_dict)
        
        # 메시지 읽음 처리
        cursor.execute('''
            UPDATE chat_message
            SET is_read = 1
            WHERE room_id = ? AND sender_id != ? AND is_read = 0
        ''', (room_id, session['user_id']))
        db.commit()
        
        return render_template('chat_room.html', 
                            room_id=room_id, 
                            messages=messages,
                            other_user=other_user,
                            product=product,
                            product_report_count=product_report_count,
                            is_seller=product and product['seller_id'] == session['user_id'] if product else False)
    except Exception as e:
        print(f"채팅방 로드 중 오류 발생: {str(e)}")
        flash('채팅방을 불러오는 중 오류가 발생했습니다.', 'error')
        return redirect(url_for('dashboard'))

# 채팅 내역 조회 페이지 추가
@app.route('/chat/history')
@login_required
def chat_history():
    # 사용자가 참여 중인 모든 채팅방 조회
    db = None
    try:
        db = get_db()
        cursor = db.cursor()
        
        # 채팅 내역에 표시할 채팅방 조회:
        # 1. 사용자가 활성 상태인 채팅방
        # 2. 사용자는 비활성 상태이지만 상대방이 새 메시지를 보낸 채팅방
        cursor.execute('''
            SELECT DISTINCT r.id, r.created_at, r.is_active,
                   (SELECT COUNT(*) FROM chat_message m 
                    WHERE m.room_id = r.id AND m.sender_id != ? AND m.is_read = 0) as unread_count,
                   (SELECT m.content FROM chat_message m 
                    WHERE m.room_id = r.id 
                    ORDER BY m.created_at DESC LIMIT 1) as last_message_content,
                   (SELECT m.created_at FROM chat_message m 
                    WHERE m.room_id = r.id 
                    ORDER BY m.created_at DESC LIMIT 1) as last_message_time,
                   (SELECT m.sender_id FROM chat_message m 
                    WHERE m.room_id = r.id 
                    ORDER BY m.created_at DESC LIMIT 1) as last_message_sender_id,
                   (SELECT u.username FROM user u 
                    WHERE u.id = (SELECT m.sender_id FROM chat_message m 
                                WHERE m.room_id = r.id 
                                ORDER BY m.created_at DESC LIMIT 1)) as last_message_sender_name,
                   p.is_active as participant_active
            FROM chat_room r
            JOIN chat_participant p ON r.id = p.room_id
            WHERE p.user_id = ? AND (
                -- 1. 사용자가 활성 상태인 채팅방
                p.is_active = 1 
                OR 
                -- 2. 사용자는 비활성 상태이지만 상대방이 새 메시지를 보낸 채팅방
                EXISTS (
                    SELECT 1 FROM chat_message m
                    WHERE m.room_id = r.id 
                    AND m.sender_id != ?
                    AND m.created_at > (
                        SELECT MAX(created_at) FROM chat_message
                        WHERE room_id = r.id AND sender_id = ?
                    )
                )
            )
            ORDER BY last_message_time DESC
        ''', (session['user_id'], session['user_id'], session['user_id'], session['user_id']))
        
        chat_rooms = []
        for row in cursor.fetchall():
            # 사용자의 마지막 메시지 이후에 새 메시지가 있는지 확인
            has_new_messages = False
            if not row['participant_active']:  # 사용자가 비활성 상태인 경우
                if row['last_message_sender_id'] != session['user_id']:
                    has_new_messages = True
            
            # 활성 상태이거나 새 메시지가 있는 경우만 추가
            if row['participant_active'] or has_new_messages:
                room = {
                    'id': row['id'],
                    'created_at': row['created_at'],
                    'unread_count': row['unread_count'] or 0,
                    'is_active': row['participant_active'],
                    'room_is_active': row['is_active'],
                    'has_new_messages': has_new_messages,
                    'last_message': None
                }
                
                if row['last_message_content']:  # 마지막 메시지가 있는 경우
                    room['last_message'] = {
                        'content': row['last_message_content'],
                        'created_at': row['last_message_time'],
                        'sender_name': row['last_message_sender_name'],
                        'sender_id': row['last_message_sender_id']
                    }
                    
                # 채팅방의 다른 참여자 정보 조회
                cursor.execute('''
                    SELECT u.id, u.username, p.is_active
                    FROM chat_participant p
                    JOIN user u ON p.user_id = u.id
                    WHERE p.room_id = ? AND p.user_id != ?
                    LIMIT 1
                ''', (room['id'], session['user_id']))
                
                other_user = cursor.fetchone()
                if other_user:
                    room['other_user'] = {
                        'id': other_user['id'],
                        'username': other_user['username'],
                        'is_active': other_user['is_active']
                    }
                
                chat_rooms.append(room)
        
        return render_template('chat_history.html', chat_rooms=chat_rooms)
    except Exception as e:
        print(f"채팅 내역 조회 중 오류 발생: {str(e)}")
        flash('채팅 내역을 불러오는 중 오류가 발생했습니다.', 'error')
        return redirect(url_for('dashboard'))

# 알림 생성 함수
def create_notification(user_id, message, link=None, notification_type='message'):
    """알림 생성 함수"""
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            INSERT INTO notifications (user_id, message, link, created_at, is_read)
            VALUES (?, ?, ?, datetime('now'), 0)
        ''', (user_id, message, link))
        notification_id = cursor.lastrowid
        db.commit()
        
        # 알림 데이터 준비
        notification = {
            'id': notification_id,
            'user_id': user_id,
            'message': message,
            'link': link,
            'is_read': False,
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'notification_type': notification_type  # 알림 타입 추가
        }
        
        # 소켓을 통해 실시간 알림 전송
        try:
            socketio.emit('notification', notification, room=f'user_{user_id}')
        except Exception as e:
            print(f"알림 소켓 전송 오류: {e}")
        
        return True
    except Exception as e:
        print(f"알림 생성 오류: {e}")
        return False

# 알림 조회 함수
@app.route('/notifications')
@login_required
def get_notifications():
    try:
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute('''
            SELECT id, message, link, is_read, created_at
            FROM notifications
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT 50
        ''', (session['user_id'],))
        
        notifications = [{
            'id': row[0],
            'message': row[1],
            'link': row[2],
            'is_read': bool(row[3]),
            'created_at': row[4]
        } for row in cursor.fetchall()]
        
        return jsonify(notifications)
    except Exception as e:
        print(f"알림 조회 중 오류 발생: {str(e)}")
        return jsonify([])

# 알림 읽음 처리 함수
@app.route('/notifications/mark-read/<int:notification_id>', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    try:
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute('''
            UPDATE notifications
            SET is_read = 1
            WHERE id = ? AND user_id = ?
        ''', (notification_id, session['user_id']))
        
        db.commit()
        return jsonify({'success': True})
    except Exception as e:
        print(f"알림 읽음 처리 중 오류 발생: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

# 모든 알림 읽음 처리 함수
@app.route('/notifications/mark-all-read', methods=['POST'])
@login_required
def mark_all_notifications_read():
    try:
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute('''
            UPDATE notifications
            SET is_read = 1
            WHERE user_id = ?
        ''', (session['user_id'],))
        
        db.commit()
        
        # AJAX 요청인 경우 JSON 응답
        if request.is_json:
            return jsonify({'success': True})
        
        # 폼 제출인 경우 이전 페이지로 리다이렉트
        referrer = request.referrer or url_for('dashboard')
        return redirect(referrer)
    except Exception as e:
        print(f"알림 전체 읽음 처리 중 오류 발생: {str(e)}")
        
        # AJAX 요청인 경우 JSON 응답
        if request.is_json:
            return jsonify({'success': False, 'error': str(e)})
        
        # 폼 제출인 경우 메시지와 함께 리다이렉트
        flash('알림 처리 중 오류가 발생했습니다.', 'error')
        return redirect(url_for('dashboard'))

# 모든 라우트에서 알림 데이터 전달
@app.context_processor
def inject_notifications():
    """모든 템플릿에 알림 정보를 주입하는 함수"""
    notifications = []
    unread_notifications_count = 0
    
    if not session.get('user_id'):
        return {
            'notifications': notifications, 
            'unread_notifications_count': unread_notifications_count, 
            'is_admin': False
        }
    
    try:
        db = get_db()
        cursor = db.cursor()
        
        # 읽지 않은 알림 수 가져오기
        cursor.execute('''
            SELECT COUNT(*) as count FROM notifications 
            WHERE user_id = ? AND is_read = 0
        ''', (session['user_id'],))
        result = cursor.fetchone()
        if result:
            unread_notifications_count = result['count']
        
        # 최근 알림 5개 가져오기
        cursor.execute('''
            SELECT * FROM notifications 
            WHERE user_id = ? 
            ORDER BY created_at DESC LIMIT 5
        ''', (session['user_id'],))
        notifications = cursor.fetchall()
        
        # 사용자 관리자 권한 정보 가져오기
        cursor.execute('SELECT is_admin FROM user WHERE id = ?', (session['user_id'],))
        user = cursor.fetchone()
        is_admin = int(user['is_admin']) if user and 'is_admin' in user else 0
        
        # 세션 업데이트
        if is_admin:
            session['is_admin'] = is_admin
        
        return {
            'notifications': notifications,
            'unread_notifications_count': unread_notifications_count,
            'is_admin': bool(is_admin)  # 불리언 값으로 변환해서 템플릿에 전달
        }
    except Exception as e:
        print(f"알림 정보 주입 중 오류 발생: {str(e)}")
        return {
            'notifications': [],
            'unread_notifications_count': 0,
            'is_admin': bool(session.get('is_admin', False))  # 불리언 값으로 변환
        }

@app.route('/payment/handle', methods=['POST'])
@login_required
def handle_payment():
    """송금 요청을 처리하는 함수"""
    # JSON 또는 Form 데이터 처리
    if request.is_json:
        data = request.get_json()
        payment_id = data.get('payment_id')
        action = data.get('action')
        product_id = data.get('product_id')
    else:
        payment_id = request.form.get('payment_id')
        action = request.form.get('action')
        product_id = request.form.get('product_id')
    
    # 기존 송금 요청 처리
    if payment_id and action:
        try:
            db = get_db()
            cursor = db.cursor()
            
            # 송금 요청 정보 조회
            cursor.execute('''
                SELECT p.*, u1.username as sender_name, u2.username as receiver_name
                FROM payment p
                JOIN user u1 ON p.sender_id = u1.id
                JOIN user u2 ON p.receiver_id = u2.id
                WHERE p.id = ? AND (p.sender_id = ? OR p.receiver_id = ?) AND p.status = 'pending'
            ''', (payment_id, session['user_id'], session['user_id']))
            
            payment = cursor.fetchone()
            if not payment:
                return jsonify({'success': False, 'message': '존재하지 않는 송금 요청입니다.'})
            
            # 권한 확인: 수신자만 승인/거절 가능, 송신자는 취소만 가능
            if action in ['accept', 'reject'] and payment['receiver_id'] != session['user_id']:
                return jsonify({'success': False, 'message': '송금 요청을 승인/거절할 권한이 없습니다.'})
            if action == 'cancel' and payment['sender_id'] != session['user_id']:
                return jsonify({'success': False, 'message': '송금 요청을 취소할 권한이 없습니다.'})
            
            # 송금 요청 상태 업데이트
            status = 'completed' if action == 'accept' else 'rejected' if action == 'reject' else 'cancelled'
            cursor.execute('''
                UPDATE payment
                SET status = ?, updated_at = datetime('now')
                WHERE id = ?
            ''', (status, payment_id))
            
            db.commit()
            
            # 송금 요청이 시작된 채팅방 찾기
            cursor.execute('''
                SELECT DISTINCT cm.room_id 
                FROM chat_message cm
                JOIN chat_participant cp1 ON cm.room_id = cp1.room_id
                JOIN chat_participant cp2 ON cm.room_id = cp2.room_id
                WHERE cm.payment_id = ? 
                AND cp1.user_id = ? AND cp2.user_id = ?
                AND cp1.is_active = 1 AND cp2.is_active = 1
                LIMIT 1
            ''', (payment_id, payment['sender_id'], payment['receiver_id']))
            original_room = cursor.fetchone()
            
            # 원래 메시지가 있는 채팅방을 찾았으면 그 채팅방 사용, 없으면 다른 활성 채팅방 찾기
            if original_room and original_room['room_id']:
                chat_room_id = original_room['room_id']
                print(f"송금 요청이 시작된 채팅방 {chat_room_id}를 사용합니다.")
            else:
                # 다른 활성 채팅방이 있는지 확인
                cursor.execute('''
                    SELECT cp1.room_id
                    FROM chat_participant cp1
                    JOIN chat_participant cp2 ON cp1.room_id = cp2.room_id
                    WHERE cp1.user_id = ? AND cp2.user_id = ? 
                    AND cp1.is_active = 1 AND cp2.is_active = 1
                    ORDER BY cp1.joined_at DESC
                    LIMIT 1
                ''', (payment['sender_id'], payment['receiver_id']))
                existing_room = cursor.fetchone()
                
                if existing_room and existing_room['room_id']:
                    chat_room_id = existing_room['room_id']
                    print(f"기존 활성 채팅방 {chat_room_id}를 사용합니다.")
                else:
                    # 이전 메시지를 찾지 못한 경우에만 새 채팅방 생성
                    chat_room_id = get_or_create_chat_room(payment['sender_id'], payment['receiver_id'])
                    print(f"새 채팅방 {chat_room_id}를 생성했습니다.")
            
            # 채팅방에 송금 응답 메시지 추가
            now = datetime.now()
            action_msg_chat = "승인됨 ✓" if status == 'completed' else "거절됨 ✗" if status == 'rejected' else "취소됨 ⊘"
            response_message = f"💰 송금 요청 ({payment['amount']:,}원): {action_msg_chat}"
            
            cursor.execute(
                'INSERT INTO chat_message (room_id, sender_id, content, created_at, payment_id) VALUES (?, ?, ?, ?, ?)',
                (chat_room_id, session['user_id'], response_message, now, payment_id)
            )
            db.commit()
            
            # 보낸 사람 정보 조회
            cursor.execute('SELECT username FROM user WHERE id = ?', (session['user_id'],))
            sender = cursor.fetchone()
            sender_name = sender['username'] if sender else '알 수 없음'
            
            # 소켓을 통해 메시지 브로드캐스트
            formatted_time = now.strftime('%Y-%m-%d %H:%M:%S')
            socketio.emit('message', {
                'sender_id': session['user_id'],
                'content': response_message,
                'created_at': formatted_time,
                'sender_name': sender_name,
                'room_id': chat_room_id,
                'payment_id': payment_id,
                'is_payment_response': True,
                'payment_status': status
            }, room=chat_room_id)
            
            # 알림 대상 및 메시지 설정
            target_id = payment['sender_id'] if session['user_id'] == payment['receiver_id'] else payment['receiver_id']
            action_msg = "승인" if status == 'completed' else "거절" if status == 'rejected' else "취소"
            
            # 알림 전송 (적절한 채팅방 링크 포함)
            create_notification(
                target_id,
                f"{payment['amount']:,}원 송금 요청이 {action_msg}되었습니다.",
                url_for('chat_history'),
                notification_type='payment_response'
            )
            
            # 승인된 경우 송금 완료 메시지 추가
            if status == 'completed':
                create_notification(
                    session['user_id'],
                    f"{payment['sender_name']}님에게 {payment['amount']:,}원 송금이 완료되었습니다.",
                    url_for('profile') + '#payment-history',
                    notification_type='payment_complete'
                )
            
            return jsonify({
                'success': True, 
                'status': status, 
                'room_id': chat_room_id,  # 채팅방 ID 반환
                'message': f'송금 요청이 {action_msg}되었습니다.'
            })
        except Exception as e:
            print(f"송금 처리 중 오류 발생: {str(e)}")
            return jsonify({'success': False, 'message': f'처리 중 오류가 발생했습니다: {str(e)}'})
    
    # 새 상품 구매 요청 처리
    elif product_id:
        try:
            db = get_db()
            cursor = db.cursor()
            
            # 상품 정보 조회
            cursor.execute('''
                SELECT p.*, u.username as seller_name 
                FROM product p 
                JOIN user u ON p.seller_id = u.id 
                WHERE p.id = ? AND p.is_deleted = 0
            ''', (product_id,))
            product = cursor.fetchone()
            
            if not product:
                flash('존재하지 않는 상품입니다.')
                return redirect(url_for('dashboard'))
            
            # 본인 상품 구매 방지
            if product['seller_id'] == session['user_id']:
                flash('자신의 상품은 구매할 수 없습니다.')
                return redirect(url_for('view_product', product_id=product_id))
            
            # 결제 ID 생성
            payment_id = str(uuid.uuid4())
            
            # 결제 정보 저장
            cursor.execute('''
                INSERT INTO payment (id, sender_id, receiver_id, product_id, amount, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, 'pending', datetime('now'), datetime('now'))
            ''', (payment_id, session['user_id'], product['seller_id'], product_id, product['price']))
            
            db.commit()
            
            # 이전에 이 사용자와 판매자 간의 채팅방 찾기
            cursor.execute('''
                SELECT cp1.room_id
                FROM chat_participant cp1
                JOIN chat_participant cp2 ON cp1.room_id = cp2.room_id
                WHERE cp1.user_id = ? AND cp2.user_id = ? AND cp1.is_active = 1 AND cp2.is_active = 1
                ORDER BY cp1.joined_at DESC
                LIMIT 1
            ''', (session['user_id'], product['seller_id']))
            
            existing_room = cursor.fetchone()
            
            if existing_room and existing_room['room_id']:
                chat_room_id = existing_room['room_id']
                print(f"기존 채팅방 {chat_room_id}를 사용합니다 (상품 구매).")
            else:
                # 채팅방 없으면 생성
                chat_room_id = get_or_create_chat_room(session['user_id'], product['seller_id'])
                print(f"새 채팅방 {chat_room_id}를 생성했습니다 (상품 구매).")
            
            # 채팅방에 구매 요청 메시지 추가
            now = datetime.now()
            payment_message = f"🛒 상품 구매 요청: '{product['title']}' ({product['price']:,}원)"
            cursor.execute(
                'INSERT INTO chat_message (room_id, sender_id, content, created_at, payment_id) VALUES (?, ?, ?, ?, ?)',
                (chat_room_id, session['user_id'], payment_message, now, payment_id)
            )
            db.commit()
            
            # 보낸 사람 정보 조회
            cursor.execute('SELECT username FROM user WHERE id = ?', (session['user_id'],))
            sender = cursor.fetchone()
            sender_name = sender['username'] if sender else '알 수 없음'
            
            # 소켓을 통해 메시지 브로드캐스트
            formatted_time = now.strftime('%Y-%m-%d %H:%M:%S')
            socketio.emit('message', {
                'sender_id': session['user_id'],
                'content': payment_message,
                'created_at': formatted_time,
                'sender_name': sender_name,
                'room_id': chat_room_id,
                'payment_id': payment_id,
                'is_product_request': True
            }, room=chat_room_id)
            
            # 판매자에게 알림 전송
            create_notification(
                product['seller_id'],
                f"{session['username']}님이 '{product['title']}' 상품에 대한 구매 요청을 보냈습니다.",
                url_for('chat_history'),
                notification_type='product_request'
            )
            
            flash('구매 요청이 전송되었습니다. 판매자의 승인을 기다려주세요.')
            return redirect(url_for('view_product', product_id=product_id))
            
        except Exception as e:
            print(f"구매 요청 중 오류 발생: {str(e)}")
            flash('구매 요청 중 오류가 발생했습니다.')
            return redirect(url_for('view_product', product_id=product_id))
    
    # 잘못된 요청
    flash('잘못된 요청입니다.')
    return redirect(url_for('dashboard'))

def add_is_deleted_column():
    with app.app_context():
        try:
            db = get_db()
            cursor = db.cursor()
            # is_deleted 컬럼이 있는지 확인
            cursor.execute("PRAGMA table_info(product)")
            columns = cursor.fetchall()
            # SQLite Row 객체는 인덱스로 접근합니다(name 필드는 인덱스 1)
            has_is_deleted = False
            for column in columns:
                if column['name'] == 'is_deleted':
                    has_is_deleted = True
                    break
            
            # is_deleted 컬럼이 없으면 추가
            if not has_is_deleted:
                cursor.execute("ALTER TABLE product ADD COLUMN is_deleted INTEGER DEFAULT 0")
                db.commit()
                print("is_deleted 컬럼이 추가되었습니다.")
        except Exception as e:
            print(f"is_deleted 컬럼 추가 중 오류 발생: {e}")

@socketio.on('edit_message')
def handle_edit_message(data):
    if 'user_id' not in session:
        return
    
    message_id = data.get('message_id')
    new_content = data.get('content')
    
    if not message_id or not new_content or len(new_content.strip()) == 0:
        return
    
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute("SELECT * FROM message WHERE id = ?", (message_id,))
    message = cursor.fetchone()
    
    if not message or message['sender_id'] != session['user_id']:
        return
    
    cursor.execute("""
        UPDATE message 
        SET content = ?, updated_at = datetime('now')
        WHERE id = ?
    """, (new_content.strip(), message_id))
    db.commit()
    
    cursor.execute("""
        SELECT m.*, u.username 
        FROM message m 
        JOIN user u ON m.sender_id = u.id 
        WHERE m.id = ?
    """, (message_id,))
    updated_message = cursor.fetchone()
    
    emit('message_edited', {
        'id': updated_message['id'],
        'content': updated_message['content'],
        'sender_id': updated_message['sender_id'],
        'username': updated_message['username'],
        'created_at': updated_message['created_at'],
        'updated_at': updated_message['updated_at']
    }, broadcast=True)

@app.route('/chat_with_seller/<string:seller_id>', methods=['GET'])
@login_required
def chat_with_seller(seller_id):
    """판매자와의 채팅을 시작하는 라우트"""
    if seller_id == session['user_id']:
        flash('자신과는 채팅할 수 없습니다.', 'error')
        return redirect(url_for('dashboard'))
    
    # URL에서 product_id 파라미터 가져오기
    product_id = request.args.get('product_id')
    
    # 채팅방 생성 또는 가져오기
    room_id = get_or_create_chat_room(session['user_id'], seller_id, product_id)
    
    # 채팅방으로 리다이렉트
    return redirect(url_for('chat_room', room_id=room_id))

def escapejs(value):
    """JavaScript 문자열을 이스케이프하는 필터"""
    if value is None:
        return ''
    value = str(value)
    value = value.replace('\\', '\\\\')
    value = value.replace('\n', '\\n')
    value = value.replace('\r', '\\r')
    value = value.replace('\t', '\\t')
    value = value.replace("'", "\\'")
    value = value.replace('"', '\\"')
    return value

app.jinja_env.filters['escapejs'] = escapejs

# 소켓 연결 이벤트 핸들러
@socketio.on('connect')
def handle_connect():
    if 'user_id' not in session:
        return False
    print(f"사용자 {session['user_id']}가 연결되었습니다.")
    return True

# 채팅방 입장 이벤트 핸들러
@socketio.on('join_room')
def handle_join_room(data):
    """채팅방 참여 처리"""
    if 'user_id' not in session:
        return False
    
    print(f"사용자 {session['user_id']} join_room 이벤트 수신: {data}")
    
    room_id = str(data.get('room_id'))  # room_id를 문자열로 확실히 변환
    
    if not room_id:
        return False
    
    # 채팅방에 사용자 추가
    join_room(room_id)
    print(f"사용자 {session['user_id']}가 채팅방 {room_id}에 입장")
    
    user_id = session['user_id']
    print(f"사용자 {user_id}가 채팅방 {room_id} 입장 시도")
    
    db = get_db()
    cursor = db.cursor()
    
    try:
        # 전역 채팅방인 경우
        if room_id == 'global_chat':
            # 전역 채팅방이 없으면 생성
            cursor.execute('SELECT id FROM chat_room WHERE id = ?', (room_id,))
            if not cursor.fetchone():
                cursor.execute('INSERT INTO chat_room (id) VALUES (?)', (room_id,))
                db.commit()
        else:
            # 1:1 채팅방인 경우 참여자 확인
            cursor.execute('''
                SELECT user_id FROM chat_participant 
                WHERE room_id = ? AND user_id = ?
            ''', (room_id, user_id))
            participant = cursor.fetchone()
            
            if not participant:
                # 참여자 확인 - 채팅방의 모든 참여자 확인
                cursor.execute("""
                    SELECT user_id FROM chat_participant WHERE room_id = ?
                """, (room_id,))
                participants = cursor.fetchall()
                
                # 참여자가 아니면 입장 불가
                participant_ids = [p['user_id'] for p in participants]
                if user_id not in participant_ids:
                    print(f"사용자 {user_id}는 채팅방 {room_id}의 참여자가 아님")
                    return False
        
        # 메시지 읽음 처리
        cursor.execute("""
            UPDATE chat_message 
            SET is_read = 1 
            WHERE room_id = ? AND sender_id != ? AND is_read = 0
        """, (room_id, user_id))
        db.commit()
        
        # 채팅방 입장
        join_room(room_id)
        
        # 입장 메시지 전송
        emit('status', {
            'msg': f'{session["username"]}님이 입장했습니다.',
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }, room=room_id)
        
        print(f"사용자 {user_id}가 채팅방 {room_id}에 입장 성공")
        
        return True
    except Exception as e:
        print(f"채팅방 입장 중 오류 발생: {str(e)}")
        return False

def create_tables():
    """앱 시작 시 필요한 데이터베이스 테이블들을 생성합니다."""
    try:
        db = sqlite3.connect(DATABASE)
        cursor = db.cursor()
        
        # user 테이블
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT,
                password TEXT NOT NULL,
                bio TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_admin INTEGER DEFAULT 0,
                is_suspended INTEGER DEFAULT 0,
                report_count INTEGER DEFAULT 0
            )
        ''')
        
        # socketio_connection 테이블 추가
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS socketio_connection (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                sid TEXT NOT NULL,
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES user (id)
            )
        ''')
        
        # product 테이블
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                price REAL NOT NULL,
                description TEXT,
                seller_id TEXT NOT NULL,
                image_url TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_deleted INTEGER DEFAULT 0,
                FOREIGN KEY (seller_id) REFERENCES user (id)
            )
        ''')
        
        # product_images 테이블
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS product_images (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                product_id TEXT NOT NULL,
                image_url TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (product_id) REFERENCES product (id)
            )
        ''')
        
        # report 테이블
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                target_type TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (reporter_id) REFERENCES user (id)
            )
        ''')
        
        # chat_room 테이블
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS chat_room (
                id TEXT PRIMARY KEY,
                user1_id TEXT,
                user2_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                product_id TEXT,
                is_active INTEGER DEFAULT 1,
                FOREIGN KEY (product_id) REFERENCES product (id)
            )
        ''')
        
        # chat_participant 테이블
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS chat_participant (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                room_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active INTEGER DEFAULT 1,
                FOREIGN KEY (room_id) REFERENCES chat_room (id),
                FOREIGN KEY (user_id) REFERENCES user (id)
            )
        ''')
        
        # chat_message 테이블
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS chat_message (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                room_id TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_read INTEGER DEFAULT 0,
                payment_id TEXT,
                FOREIGN KEY (room_id) REFERENCES chat_room (id),
                FOREIGN KEY (sender_id) REFERENCES user (id),
                FOREIGN KEY (payment_id) REFERENCES payment (id)
            )
        ''')
        
        # payment 테이블
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS payment (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                product_id TEXT,
                amount REAL NOT NULL,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_id) REFERENCES user (id),
                FOREIGN KEY (receiver_id) REFERENCES user (id),
                FOREIGN KEY (product_id) REFERENCES product (id)
            )
        ''')
        
        # notifications 테이블
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS notifications (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                message TEXT NOT NULL,
                link TEXT,
                is_read INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES user (id)
            )
        ''')
        
        # 전역 채팅방 생성 (없는 경우)
        cursor.execute("SELECT id FROM chat_room WHERE id = 'global_chat'")
        if not cursor.fetchone():
            cursor.execute("INSERT INTO chat_room (id) VALUES ('global_chat')")
        
        # 관리자 계정 추가 (없는 경우)
        admin_username = 'admin'
        admin_password = 'admin123!'
        
        # 관리자 계정이 이미 존재하는지 확인
        cursor.execute("SELECT * FROM user WHERE username = ?", (admin_username,))
        if not cursor.fetchone():
            admin_id = str(uuid.uuid4())
            hashed_password = hash_password(admin_password)
            cursor.execute("""
                INSERT INTO user (id, username, password, created_at, updated_at, is_admin)
                VALUES (?, ?, ?, datetime('now'), datetime('now'), 1)
            """, (admin_id, admin_username, hashed_password))
            print("관리자 계정이 생성되었습니다. 사용자명: admin, 비밀번호: admin123!")
        
        db.commit()
        print("데이터베이스 테이블이 성공적으로 생성되었습니다.")
        
    except Exception as e:
        print(f"데이터베이스 테이블 생성 중 오류 발생: {e}")
        db.rollback()
    finally:
        db.close()

@app.route('/payment/create', methods=['POST'])
@login_required
def create_payment():
    """송금 요청을 생성하는 함수"""
    if not request.is_json:
        return jsonify({'success': False, 'message': '잘못된 요청 형식입니다.'})
    
    data = request.get_json()
    receiver_id = data.get('receiver_id')
    amount = data.get('amount')
    
    if not receiver_id or not amount or amount <= 0:
        return jsonify({'success': False, 'message': '모든 필드를 올바르게 입력해주세요.'})
    
    try:
        db = get_db()
        cursor = db.cursor()
        
        # 수신자 존재 여부 확인
        cursor.execute('SELECT id FROM user WHERE id = ?', (receiver_id,))
        if not cursor.fetchone():
            return jsonify({'success': False, 'message': '존재하지 않는 사용자입니다.'})
        
        # 자신에게 송금 요청 방지
        if receiver_id == session['user_id']:
            return jsonify({'success': False, 'message': '자신에게 송금을 요청할 수 없습니다.'})
        
        # 결제 ID 생성
        payment_id = str(uuid.uuid4())
        
        # 결제 정보 저장
        cursor.execute('''
            INSERT INTO payment (id, sender_id, receiver_id, amount, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'pending', datetime('now'), datetime('now'))
        ''', (payment_id, session['user_id'], receiver_id, amount))
        
        db.commit()
        
        # 이전에 이 사용자들 간의 채팅방 찾기 (is_active가 1인 경우만)
        cursor.execute('''
            SELECT cp1.room_id
            FROM chat_participant cp1
            JOIN chat_participant cp2 ON cp1.room_id = cp2.room_id
            WHERE cp1.user_id = ? AND cp2.user_id = ? AND cp1.is_active = 1 AND cp2.is_active = 1
            ORDER BY cp1.joined_at DESC
            LIMIT 1
        ''', (session['user_id'], receiver_id))
        
        existing_room = cursor.fetchone()
        
        if existing_room and existing_room['room_id']:
            chat_room_id = existing_room['room_id']
            print(f"기존 채팅방 {chat_room_id}를 사용합니다.")
        else:
            # 채팅방 없으면 생성
            chat_room_id = get_or_create_chat_room(session['user_id'], receiver_id)
            print(f"새 채팅방 {chat_room_id}를 생성했습니다.")
        
        # 채팅방에 송금 요청 메시지 추가
        now = datetime.now()
        payment_message = f"💰 송금 요청: {amount:,}원"
        cursor.execute(
            'INSERT INTO chat_message (room_id, sender_id, content, created_at, payment_id) VALUES (?, ?, ?, ?, ?)',
            (chat_room_id, session['user_id'], payment_message, now, payment_id)
        )
        db.commit()
        
        # 보낸 사람 정보 조회
        cursor.execute('SELECT username FROM user WHERE id = ?', (session['user_id'],))
        sender = cursor.fetchone()
        sender_name = sender['username'] if sender else '알 수 없음'
        
        # 소켓을 통해 메시지 브로드캐스트
        formatted_time = now.strftime('%Y-%m-%d %H:%M:%S')
        socketio.emit('message', {
            'sender_id': session['user_id'],
            'content': payment_message,
            'created_at': formatted_time,
            'sender_name': sender_name,
            'room_id': chat_room_id,
            'payment_id': payment_id,
            'is_payment_request': True
        }, room=chat_room_id)
        
        # 수신자에게 알림 전송 (알림 타입을 payment_request로 지정)
        create_notification(
            receiver_id,
            f"{session['username']}님이 {amount:,}원의 송금을 요청했습니다.",
            url_for('chat_history'),
            notification_type='payment_request'
        )
        
        return jsonify({
            'success': True, 
            'payment_id': payment_id,
            'room_id': chat_room_id,  # 채팅방 ID 추가
            'message_sent': True  # 메시지가 이미 전송되었음을 알림
        })
    except Exception as e:
        print(f"송금 요청 생성 중 오류 발생: {str(e)}")
        return jsonify({'success': False, 'message': '처리 중 오류가 발생했습니다.'})

def add_payment_id_column():
    """채팅 메시지 테이블에 payment_id 컬럼을 추가합니다."""
    try:
        db = sqlite3.connect(DATABASE)
        cursor = db.cursor()
        
        # payment_id 컬럼이 있는지 확인
        cursor.execute("PRAGMA table_info(chat_message)")
        columns = cursor.fetchall()
        
        # 컬럼 이름 확인
        has_payment_id = False
        for column in columns:
            if column[1] == 'payment_id':  # SQLite PRAGMA 결과에서 인덱스 1이 컬럼 이름
                has_payment_id = True
                break
        
        # payment_id 컬럼이 없으면 추가
        if not has_payment_id:
            cursor.execute("ALTER TABLE chat_message ADD COLUMN payment_id TEXT")
            db.commit()
            print("chat_message 테이블에 payment_id 컬럼이 추가되었습니다.")
        
    except Exception as e:
        print(f"payment_id 컬럼 추가 중 오류 발생: {e}")
        db.rollback()
    finally:
        db.close()

# 소켓 알림 룸 참여 이벤트 핸들러
@socketio.on('join_notification_room')
def join_notification_room(data):
    """사용자별 알림 룸 참여 핸들러"""
    if 'user_id' not in session:
        return False
    
    user_id = data.get('user_id')
    if not user_id or user_id != session['user_id']:
        return False
    
    # 사용자별 알림 룸 생성 (user_사용자ID 형식)
    notification_room = f'user_{user_id}'
    join_room(notification_room)
    print(f"사용자 {user_id}가 알림 룸 {notification_room}에 참여했습니다.")
    return True

@app.route('/leave_chat_room/<room_id>')
@login_required
def leave_chat_room_old(room_id):
    db = None
    try:
        db = get_db()
        cursor = db.cursor()
        
        # 채팅방 존재 여부 확인
        cursor.execute('SELECT id FROM chat_room WHERE id = ?', (room_id,))
        room = cursor.fetchone()
        
        if not room:
            flash('존재하지 않는 채팅방입니다.', 'error')
            return redirect(url_for('dashboard'))
        
        # 사용자가 참여자인지 확인
        cursor.execute('''
            SELECT room_id, user_id FROM chat_participant 
            WHERE room_id = ? AND user_id = ?
        ''', (room_id, session['user_id']))
        participant = cursor.fetchone()
        
        if not participant:
            flash('참여하지 않은 채팅방은 나갈 수 없습니다.', 'error')
            return redirect(url_for('dashboard'))
        
        # 채팅 참여자 정보 조회 (다른 참여자 확인)
        cursor.execute('''
            SELECT user_id FROM chat_participant
            WHERE room_id = ? AND user_id != ?
        ''', (room_id, session['user_id']))
        other_participant = cursor.fetchone()
        
        # 나가기 메시지 추가
        cursor.execute('''
            INSERT INTO chat_message (room_id, sender_id, content, created_at)
            VALUES (?, ?, ?, datetime('now'))
        ''', (room_id, session['user_id'], '👋 채팅방을 나갔습니다.'))
        
        # 사용자를 채팅방에서 제거
        cursor.execute('''
            DELETE FROM chat_participant
            WHERE room_id = ? AND user_id = ?
        ''', (room_id, session['user_id']))
        
        # 상대방이 있으면 상대방에게 알림
        if other_participant:
            try:
                # 상대방에게 알림 생성
                create_notification(
                    other_participant['user_id'],
                    f'상대방이 채팅방을 나갔습니다.',
                    url_for('chat_room', room_id=room_id),
                    'chat'
                )
                
                # 소켓 이벤트 발송
                socketio.emit('user_left', {
                    'user_id': session['user_id'],
                    'room_id': room_id,
                    'message': '👋 상대방이 채팅방을 나갔습니다.'
                }, room=room_id)
            except Exception as socket_error:
                app.logger.error(f"채팅방 나가기 알림 전송 오류: {str(socket_error)}")
                # 알림 전송이 실패해도 계속 진행
        else:
            # 상대방이 없으면 채팅방 삭제
            cursor.execute('DELETE FROM chat_message WHERE room_id = ?', (room_id,))
            cursor.execute('DELETE FROM chat_room WHERE id = ?', (room_id,))
        
        db.commit()
        flash('채팅방에서 나갔습니다.', 'success')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        app.logger.error(f"채팅방 나가기 오류: {str(e)}")
        app.logger.exception("상세 오류 정보:")
        if db is not None:
            db.rollback()
        flash('채팅방 나가기 중 오류가 발생했습니다.', 'error')
        return redirect(url_for('dashboard'))

def add_product_id_column():
    """chat_room 테이블에 product_id 컬럼을 추가합니다."""
    try:
        db = sqlite3.connect(DATABASE)
        cursor = db.cursor()
        
        # product_id 컬럼이 있는지 확인
        cursor.execute("PRAGMA table_info(chat_room)")
        columns = cursor.fetchall()
        
        # 컬럼 이름 확인
        has_product_id = False
        for column in columns:
            if column[1] == 'product_id':  # SQLite PRAGMA 결과에서 인덱스 1이 컬럼 이름
                has_product_id = True
                break
        
        # product_id 컬럼이 없으면 추가
        if not has_product_id:
            cursor.execute("ALTER TABLE chat_room ADD COLUMN product_id TEXT")
            db.commit()
            print("chat_room 테이블에 product_id 컬럼이 추가되었습니다.")
        
    except Exception as e:
        print(f"product_id 컬럼 추가 중 오류 발생: {e}")
        db.rollback()
    finally:
        db.close()

@socketio.on('send_message')
def handle_message(data):
    """채팅 메시지 전송 처리(속도 제한 추가)"""
    if 'user_id' not in session:
        return False
    
    user_id = session['user_id']
    room_id = str(data.get('room_id'))  # room_id를 문자열로 확실히 변환
    content = sanitize_input(data.get('content', ''))
    
    if not room_id or not content or content.strip() == '':
        return False
    
    # 메시지 속도 제한 적용
    current_time = datetime.now()
    if user_id in user_message_timestamps:
        timestamps = user_message_timestamps[user_id]
        # 최근 MESSAGE_TIMEFRAME초 동안의 메시지만 유지
        timestamps = [ts for ts in timestamps if (current_time - ts).total_seconds() < MESSAGE_TIMEFRAME]
        
        # 메시지 수가 제한을 초과하면 차단
        if len(timestamps) >= MESSAGE_LIMIT:
            emit('error', {'message': '메시지 전송 속도가 너무 빠릅니다. 잠시 후 다시 시도해주세요.'})
            return False
        
        # 현재 메시지 타임스탬프 추가
        timestamps.append(current_time)
        user_message_timestamps[user_id] = timestamps
    else:
        user_message_timestamps[user_id] = [current_time]
    
    print(f"사용자 {user_id}가 채팅방 {room_id}에 메시지 전송: {content}")
    
    try:
        db = get_db()
        cursor = db.cursor()
        
        # 현재 사용자 정보 조회
        cursor.execute('SELECT username FROM user WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user:
            print(f"메시지 전송 실패: 사용자 {user_id} 정보를 찾을 수 없음")
            return False
        
        # 메시지 저장
        now = datetime.now()
        cursor.execute('''
            INSERT INTO chat_message (room_id, sender_id, content, created_at, is_read)
            VALUES (?, ?, ?, ?, 0)
        ''', (room_id, user_id, content, now))
        
        # 방의 다른 참여자 찾기
        cursor.execute('''
            SELECT user_id FROM chat_participant
            WHERE room_id = ? AND user_id != ?
        ''', (room_id, user_id))
        
        recipients = cursor.fetchall()
        db.commit()
        
        # 메시지 브로드캐스트
        formatted_time = now.strftime('%Y-%m-%d %H:%M:%S')
        message_data = {
            'sender_id': user_id,
            'content': content,
            'created_at': formatted_time,
            'sender_name': user['username'],
            'room_id': room_id
        }
        
        socketio.emit('message', message_data, room=room_id)
        
        # 다른 참여자들에게 알림 전송
        for recipient in recipients:
            recipient_id = recipient['user_id']
            create_notification(
                recipient_id,
                f"{user['username']}님의 메시지: {content[:20]}{'...' if len(content) > 20 else ''}",
                url_for('chat_room', room_id=room_id),
                notification_type='message'
            )
        
        return True
    except Exception as e:
        print(f"메시지 전송 중 오류 발생: {str(e)}")
        return False

@app.route('/chat/leave/<room_id>', methods=['POST'])
@login_required
def leave_chat_room(room_id):
    db = None
    try:
        db = get_db()
        cursor = db.cursor()
        
        # 채팅방 정보 조회
        cursor.execute('SELECT id FROM chat_room WHERE id = ?', (room_id,))
        room = cursor.fetchone()
        if not room:
            flash('존재하지 않는 채팅방입니다.', 'error')
            return redirect(url_for('chat_history'))
            
        # 나가기 메시지 추가
        cursor.execute('''
            INSERT INTO chat_message (room_id, sender_id, content, created_at)
            VALUES (?, ?, ?, datetime('now'))
        ''', (room_id, session['user_id'], '👋 채팅방을 나갔습니다.'))
        
        # 채팅방 참여자 상태를 비활성화로 변경
        cursor.execute('''
            UPDATE chat_participant 
            SET is_active = 0 
            WHERE room_id = ? AND user_id = ?
        ''', (room_id, session['user_id']))
        
        # 채팅방에 남은 활성 참여자 수 확인
        cursor.execute('''
            SELECT COUNT(*) as active_count
            FROM chat_participant
            WHERE room_id = ? AND is_active = 1
        ''', (room_id,))
        
        active_count = cursor.fetchone()['active_count']
        
        # 모든 참여자가 나간 경우 채팅방과 메시지를 삭제
        if active_count == 0:
            # 채팅 메시지 삭제
            cursor.execute('DELETE FROM chat_message WHERE room_id = ?', (room_id,))
            
            # 채팅 참여자 정보 삭제
            cursor.execute('DELETE FROM chat_participant WHERE room_id = ?', (room_id,))
            
            # 채팅방 삭제
            cursor.execute('DELETE FROM chat_room WHERE id = ?', (room_id,))
            
            print(f"모든 참여자가 나가 채팅방 {room_id}을(를) 삭제했습니다.")
        else:
            # 다른 참여자에게 알림 전송
            cursor.execute('''
                SELECT user_id FROM chat_participant
                WHERE room_id = ? AND user_id != ? AND is_active = 1
            ''', (room_id, session['user_id']))
            
            for row in cursor.fetchall():
                other_user_id = row['user_id']
                # 나간 사용자에 대한 알림 생성
                create_notification(
                    other_user_id,
                    f"{session['username']}님이 채팅방을 나갔습니다.",
                    url_for('chat_room', room_id=room_id),
                    'chat'
                )
            
            # 소켓 이벤트 발송
            socketio.emit('user_left', {
                'user_id': session['user_id'],
                'username': session['username'],
                'room_id': room_id,
                'message': f"{session['username']}님이 채팅방을 나갔습니다."
            }, room=room_id)
        
        db.commit()
        flash('채팅방을 나갔습니다.', 'success')
        return redirect(url_for('chat_history'))
    except Exception as e:
        if db:
            db.rollback()
        print(f"채팅방 나가기 중 오류 발생: {str(e)}")
        flash('채팅방을 나가는 중 오류가 발생했습니다.', 'error')
        return redirect(url_for('chat_history'))

@app.route('/chat/join/<room_id>', methods=['POST'])
@login_required
def join_chat_room(room_id):
    db = None
    try:
        db = get_db()
        cursor = db.cursor()
        
        # 채팅방 존재 여부 확인
        cursor.execute('SELECT id, is_active FROM chat_room WHERE id = ?', (room_id,))
        room = cursor.fetchone()
        
        if not room:
            flash('존재하지 않는 채팅방입니다.', 'error')
            return redirect(url_for('chat_history'))
        
        # 채팅방이 비활성화된 경우 활성화
        if not room['is_active']:
            cursor.execute('''
                UPDATE chat_room
                SET is_active = 1
                WHERE id = ?
            ''', (room_id,))
        
        # 참여자 상태를 활성화로 변경
        cursor.execute('''
            UPDATE chat_participant 
            SET is_active = 1 
            WHERE room_id = ? AND user_id = ?
        ''', (room_id, session['user_id']))
        
        # 입장 메시지 추가
        cursor.execute('''
            INSERT INTO chat_message (room_id, sender_id, content, created_at)
            VALUES (?, ?, ?, datetime('now'))
        ''', (room_id, session['user_id'], '👋 채팅방에 다시 입장했습니다.'))
        
        db.commit()
        
        # 소켓 이벤트 발송
        socketio.emit('user_joined', {
            'user_id': session['user_id'],
            'room_id': room_id,
            'message': f"{session['username']}님이 채팅방에 다시 입장했습니다."
        }, room=room_id)
        
        flash('채팅방에 다시 입장했습니다.', 'success')
        return redirect(url_for('chat_room', room_id=room_id))
    except Exception as e:
        if db:
            db.rollback()
        print(f"채팅방 입장 중 오류 발생: {str(e)}")
        flash('채팅방 입장 중 오류가 발생했습니다.', 'error')
        return redirect(url_for('chat_history'))

def add_is_active_column():
    """chat_participant 테이블에 is_active 컬럼을 추가합니다."""
    try:
        db = sqlite3.connect(DATABASE)
        cursor = db.cursor()
        
        # is_active 컬럼이 있는지 확인
        cursor.execute("PRAGMA table_info(chat_participant)")
        columns = cursor.fetchall()
        
        # 컬럼 이름 확인
        has_is_active = False
        for column in columns:
            if column[1] == 'is_active':  # SQLite PRAGMA 결과에서 인덱스 1이 컬럼 이름
                has_is_active = True
                break
        
        # is_active 컬럼이 없으면 추가
        if not has_is_active:
            cursor.execute("ALTER TABLE chat_participant ADD COLUMN is_active INTEGER DEFAULT 1")
            db.commit()
            print("chat_participant 테이블에 is_active 컬럼이 추가되었습니다.")
        
    except Exception as e:
        print(f"is_active 컬럼 추가 중 오류 발생: {e}")
        db.rollback()
    finally:
        db.close()

# 보안 헤더 설정을 위한 미들웨어
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdn.socket.io https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data:; font-src 'self'; connect-src 'self' wss: ws:;"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# 로그인 실패 관리를 위한 전역 변수
login_attempts = {}

# XSS 방어를 위한 입력 정화 함수
def sanitize_input(text):
    """XSS 공격 방지를 위한 입력 정화 함수"""
    if not text:
        return ""
    # HTML 태그 이스케이프 처리
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = text.replace('"', "&quot;").replace("'", "&#x27;")
    return text

# 회원가입 함수
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        
        # 입력값 검증
        if not username or not password or not confirm_password:
            flash('사용자명과 비밀번호를 모두 입력해주세요.')
            return redirect(url_for('register'))
        
        # 사용자명 길이 및 문자 제한
        if len(username) < 3 or len(username) > 20:
            flash('사용자명은 3자 이상 20자 이하여야 합니다.')
            return redirect(url_for('register'))
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            flash('사용자명은 영문, 숫자, 언더스코어(_)만 사용할 수 있습니다.')
            return redirect(url_for('register'))
        
        # 비밀번호 강도 검증
        if len(password) < 7:
            flash('비밀번호는 7자 이상이어야 합니다.')
            return redirect(url_for('register'))
        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{7,}$', password):
            flash('비밀번호는 영문, 숫자, 특수문자를 포함해야 합니다.')
            return redirect(url_for('register'))
        if password != confirm_password:
            flash('비밀번호가 일치하지 않습니다.')
            return redirect(url_for('register'))
        
        db = get_db()
        cursor = db.cursor()
        
        # 중복 사용자 체크 - 사용자명 중복 확인
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))
        
        # 비밀번호 해싱
        hashed_password = hash_password(password)
        
        # 사용자 등록
        user_id = str(uuid.uuid4())
        try:
            cursor.execute("""
                INSERT INTO user (id, username, password, created_at, updated_at)
                VALUES (?, ?, ?, datetime('now'), datetime('now'))
            """, (user_id, username, hashed_password))
            db.commit()
            flash('회원가입이 완료되었습니다. 로그인 해주세요.')
            return redirect(url_for('login'))
        except Exception as e:
            db.rollback()
            flash('회원가입 중 오류가 발생했습니다.')
            app.logger.error(f'회원가입 오류: {str(e)}')
            return redirect(url_for('register'))
    
    return render_template('register.html')

# 메시지 속도 제한을 위한 변수 설정
user_message_timestamps = {}
MESSAGE_LIMIT = 5  # 5초당 최대 5개 메시지
MESSAGE_TIMEFRAME = 5  # 초

if __name__ == '__main__':
    # 데이터베이스 초기화
    create_tables()
    
    # 필요한 마이그레이션 실행
    add_payment_id_column()
    add_product_id_column()  # product_id 컬럼 추가
    add_is_active_column()  # is_active 컬럼 추가
    
    # 앱 실행
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
    