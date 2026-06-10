"""
================================================================================
  AI外贸邮件生成器 Pro - 完整增强版 (单文件)
  
  功能模块:
  ✅ 安全模块 (8层纵深防御: AES-256-GCM加密/速率限制/CSRF/输入净化/脱敏/审计日志)
  ✅ 单封邮件生成 (15国风格 / 20+场景 / AI驱动)
  ✅ 📧 群发模块 (一键导入Excel/CSV客户列表 → 批量生成 → 一键发送)
  ✅ SMTP邮件发送 (支持阿里云企业邮箱/Gmail/Outlook等)
  ✅ 历史记录 / 导出TXT+Word / 一键复制
  
  安全说明:
  ⚠️  所有敏感配置（API Key、数据库凭证）均通过环境变量/Streamlit Secrets 加载
  ⚠️  请勿在代码中硬编码任何密钥
  
  运行: streamlit run AI_ForeignTrade_Email_Pro.py
================================================================================
"""
import streamlit as st
from openai import OpenAI
from typing import List, Dict, Optional, Any, Tuple
import json
import os
import re

# ====== 加载环境变量 / Streamlit Secrets ======
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # Streamlit Cloud 使用 st.secrets，无需 dotenv
import sys
import hashlib
import hmac
import base64
import secrets
import time
import uuid
import logging
import struct
import smtplib
import pandas as pd
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header
from datetime import datetime, timedelta
from io import BytesIO
from pathlib import Path
from docx import Document

# ============================================================================
# ====================== 🔐 Supabase 认证模块 ===============================
# ============================================================================

# 从环境变量 / Streamlit Secrets 加载敏感配置（禁止硬编码）
def _get_secret(key: str, default: str = "") -> str:
    """优先环境变量 -> Streamlit Secrets -> 默认值"""
    env_val = os.environ.get(key, "")
    if env_val:
        return env_val
    try:
        secrets_val = st.secrets.get(key, "")
        if secrets_val:
            return secrets_val
    except Exception:
        pass
    return default

SUPABASE_URL = _get_secret("SUPABASE_URL")
SUPABASE_ANON_KEY = _get_secret("SUPABASE_ANON_KEY")

try:
    from supabase import create_client, Client
    _SUPABASE_AVAILABLE = True
except ImportError:
    _SUPABASE_AVAILABLE = False
    Client = None


def get_supabase_client() -> Optional[Client]:
    """获取 Supabase 客户端实例（单例模式）"""
    if not _SUPABASE_AVAILABLE:
        return None
    if 'sb_client' not in st.session_state:
        st.session_state.sb_client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
    return st.session_state.sb_client


class AuthManager:
    """认证管理器"""
    
    @staticmethod
    def init_session_state():
        """初始化会话状态"""
        defaults = {
            'auth_initialized': True,
            'user': None,
            'user_email': None,
            'user_id': None,
            'is_admin': False,
            'user_profile': None,
        }
        for key, val in defaults.items():
            if key not in st.session_state:
                st.session_state[key] = val
    
    @staticmethod
    def login(email: str, password: str) -> Tuple[bool, str]:
        """用户登录（带重试机制，profile查询失败不阻塞登录）"""
        import time as _time
        
        sb = get_supabase_client()
        if not sb:
            return False, "Supabase 客户端不可用，请安装 supabase 库"
        
        # 重试最多3次（解决Streamlit Cloud冷启动延迟问题）
        max_retries = 3
        last_error = ""
        for attempt in range(max_retries):
            try:
                response = sb.auth.sign_in_with_password({"email": email, "password": password})
                if response.user:
                    st.session_state.user = response.user
                    st.session_state.user_email = response.user.email
                    st.session_state.user_id = response.user.id
                    
                    # 尝试获取用户profile（含管理员权限），失败不阻塞登录
                    try:
                        profile = sb.table('user_profiles').select('*').eq('id', response.user.id).execute()
                        if profile.data:
                            st.session_state.user_profile = profile.data[0]
                            st.session_state.is_admin = profile.data[0].get('is_admin', False)
                    except Exception as profile_err:
                        # RLS策略问题等不影响正常登录，记录日志即可
                        print(f"[WARN] 获取user_profile失败(不影响登录): {profile_err}")
                    
                    # 强制刷新session确保状态保存
                    st.session_state._login_time = _time.time()
                    
                    return True, "登录成功"
                else:
                    last_error = "邮箱或密码错误"
            except Exception as e:
                last_error = str(e)
                if attempt < max_retries - 1:
                    _time.sleep(1)  # 等待1秒后重试
        
        return False, f"登录失败: {last_error}"
    
    @staticmethod
    def register(email: str, password: str, display_name: str = "") -> Tuple[bool, str]:
        """用户注册"""
        sb = get_supabase_client()
        if not sb:
            return False, "Supabase 客户端不可用"
        try:
            response = sb.auth.sign_up({
                "email": email,
                "password": password,
                "options": {
                    "data": {"display_name": display_name or email.split('@')[0]}
                }
            })
            if response.user:
                return True, "注册成功！请查收验证邮件并激活账号"
            return False, "注册失败"
        except Exception as e:
            return False, f"注册失败: {str(e)}"
    
    @staticmethod
    def logout():
        """用户登出"""
        sb = get_supabase_client()
        if sb:
            sb.auth.sign_out()
        st.session_state.user = None
        st.session_state.user_email = None
        st.session_state.user_id = None
        st.session_state.is_admin = False
        st.session_state.user_profile = None
    
    @staticmethod
    def is_authenticated() -> bool:
        """检查是否已登录"""
        return st.session_state.get('user') is not None and st.session_state.get('user_email') is not None
    
    @staticmethod
    def get_user_email() -> Optional[str]:
        """获取当前用户邮箱"""
        return st.session_state.get('user_email')
    
    @staticmethod
    def is_admin() -> bool:
        """检查是否为管理员"""
        return st.session_state.get('is_admin', False)


def render_login_page():
    """渲染登录页面"""
    st.set_page_config(page_title="AI外贸邮件 - 登录", page_icon="📧", layout="centered")
    
    # 隐藏 Streamlit Cloud 右下角 GitHub 头像
    st.markdown("""<style>
        [data-testid="stAppViewBlockContainer"] [data-testid="stVerticalBlock"] > [style*="flex-direction: column"] > [data-testid="stVerticalBlock"]:last-child { display: none !important; }
        [data-testid="stAppViewBlockContainer"] [data-testid="stToolbar"] + div[style*="position: fixed"] { display: none !important; }
        .viewerBadge_container { display: none !important; }
        iframe[title*="streamlit"] { display: none !important; }
    </style>""", unsafe_allow_html=True)
    
    # 居中显示Logo
    st.markdown("""
    <div style="text-align: center; padding: 20px;">
        <h1>📧 AI外贸邮件生成器 Pro</h1>
        <p style="color: gray;">智能外贸开发信生成与群发系统</p>
    </div>
    """, unsafe_allow_html=True)
    
    st.divider()
    
    # 登录/注册切换
    tab_login, tab_register = st.tabs(["🔐 登录", "📝 注册"])
    
    with tab_login:
        with st.form("login_form", clear_on_submit=True):
            st.markdown("### 登录账号")
            email = st.text_input("📧 邮箱", placeholder="your@email.com", autocomplete="email")
            password = st.text_input("🔒 密码", type="password", autocomplete="current-password")
            
            col1, col2 = st.columns(2)
            with col1:
                submitted = st.form_submit_button("登录", use_container_width=True, type="primary")
            
            if submitted:
                if not email or not password:
                    st.error("请填写邮箱和密码")
                else:
                    with st.spinner("登录中..."):
                        success, msg = AuthManager.login(email, password)
                        if success:
                            st.success(msg)
                            st.rerun()
                        else:
                            st.error(msg)
    
    with tab_register:
        with st.form("register_form", clear_on_submit=True):
            st.markdown("### 注册账号")
            reg_email = st.text_input("📧 邮箱", placeholder="your@email.com", autocomplete="email")
            reg_name = st.text_input("👤 显示名称", placeholder="你的名字", autocomplete="name")
            reg_password = st.text_input("🔒 密码", type="password", autocomplete="new-password")
            reg_password2 = st.text_input("🔒 确认密码", type="password", autocomplete="new-password")
            
            submitted = st.form_submit_button("注册", use_container_width=True, type="primary")
            
            if submitted:
                if not reg_email or not reg_password:
                    st.error("请填写所有必填项")
                elif reg_password != reg_password2:
                    st.error("两次密码不一致")
                elif len(reg_password) < 6:
                    st.error("密码至少6位")
                else:
                    with st.spinner("注册中..."):
                        success, msg = AuthManager.register(reg_email, reg_password, reg_name)
                        if success:
                            st.success(msg)
                            st.info("请前往邮箱验证账号后登录")
                        else:
                            st.error(msg)
    
    st.divider()
    st.caption("🔒 请使用注册账号登录，或点击上方「注册」创建新账号")


def require_auth():
    """认证守卫 - 强制登录"""
    AuthManager.init_session_state()
    
    if not AuthManager.is_authenticated():
        render_login_page()
        st.stop()
        return False
    return True

# ============================================================================
# ====================== 🛡️ 安全模块 (Security Module) ======================
# ============================================================================

# --- 加密模块 (AES-256-GCM) ---
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False
    AESGCM = None
    PBKDF2HMAC = None


class CryptoVault:
    """AES-256-GCM 加密保险箱"""
    _SALT_FILE = ".crypto_salt"
    _KEY_ITERATIONS = 600_000

    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                         iterations=CryptoVault._KEY_ITERATIONS, backend=default_backend())
        return kdf.derive(password.encode('utf-8'))

    @classmethod
    def _get_machine_fingerprint(cls) -> str:
        try:
            parts = [os.environ.get('COMPUTERNAME', ''), os.environ.get('USERNAME', '')]
            if os.name == 'nt':
                parts.append(os.environ.get('PROCESSOR_IDENTIFIER', ''))
            return hashlib.sha256('|'.join(parts).encode()).hexdigest()
        except Exception:
            return hashlib.sha256(b'default_fingerprint').hexdigest()

    @classmethod
    def encrypt(cls, plaintext: str) -> str:
        if not _CRYPTO_AVAILABLE:
            return base64.b64encode(plaintext.encode()).decode()
        password = cls._get_machine_fingerprint()
        salt = os.urandom(16)
        key = cls._derive_key(password, salt)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        combined = salt + nonce + ciphertext
        return base64.b64encode(combined).decode('utf-8')

    @classmethod
    def decrypt(cls, encrypted: str) -> Optional[str]:
        if not _CRYPTO_AVAILABLE:
            try:
                return base64.b64decode(encrypted.encode()).decode()
            except Exception:
                return None
        try:
            password = cls._get_machine_fingerprint()
            raw = base64.b64decode(encrypted.encode('utf-8'))
            salt, nonce, ciphertext = raw[:16], raw[16:28], raw[28:]
            key = cls._derive_key(password, salt)
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode('utf-8')
        except Exception:
            return None


class InputSanitizer:
    """输入净化器"""
    _SQL_PATTERNS = re.compile(r"(?i)(\b(select|insert|update|delete|drop|alter|create|exec|execute|union|truncate|declare)\b)")
    _XSS_PATTERNS = re.compile(r'<script|javascript:|on\w+\s*=|&#x|&#\d+', re.IGNORECASE)
    _PATH_TRAVERSAL = re.compile(r'\.\./|\.\.\\|%2e%2e|%252e')
    _CRLF_PATTERN = re.compile(r'[\r\n]')
    _PROMPT_INJECTION = re.compile(
        r'(?i)(ignore\s+(all\s+)?(previous|above|prior)\s+(instructions?|prompts?|directives?|rules?)|'
        r'system\s*:\s*|you\s+are\s+now|new\s+instructions?\s*:|'
        r'forget\s+everything|disregard\s+all)')

    @classmethod
    def sanitize_input(cls, text: str, max_length: int = 5000) -> Tuple[str, List[str]]:
        warnings = []
        if not text:
            return text, warnings
        if len(text) > max_length:
            text = text[:max_length]
            warnings.append(f"输入被截断至{max_length}字符")
        if cls._CRLF_PATTERN.search(text):
            warnings.append("检测到换行注入尝试")
            text = cls._CRLF_PATTERN.sub(' ', text)
        if cls._SQL_PATTERNS.search(text):
            warnings.append("检测到疑似SQL注入模式")
        if cls._XSS_PATTERNS.search(text):
            warnings.append("检测到疑似XSS攻击模式")
            text = cls._XSS_PATTERNS.sub('[FILTERED]', text)
        if cls._PROMPT_INJECTION.search(text):
            warnings.append("检测到疑似Prompt注入尝试")
        if cls._PATH_TRAVERSAL.search(text):
            warnings.append("检测到路径穿越尝试")
            text = cls._PATH_TRAVERSAL.sub('', text)
        return text.strip(), warnings

    @classmethod
    def sanitize_email_address(cls, email: str) -> Tuple[str, bool]:
        if not email:
            return email, False
        email = email.strip()
        pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        if pattern.match(email) and len(email) <= 254:
            return email, True
        return email, False

    @classmethod
    def sanitize_filename(cls, filename: str) -> str:
        if not filename:
            return "untitled"
        filename = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', filename)
        filename = filename.strip('. ')
        return filename or "untitled"


class DataMasker:
    """数据脱敏器"""
    @staticmethod
    def mask_email(email: str) -> str:
        if not email or '@' not in email:
            return email
        local, domain = email.split('@', 1)
        if len(local) <= 2:
            masked = local[0] + '***'
        elif len(local) <= 4:
            masked = local[:2] + '***'
        else:
            masked = local[:3] + '***' + local[-1]
        return f"{masked}@{domain}"

    @staticmethod
    def mask_api_key(key: str) -> str:
        if not key or len(key) < 8:
            return '***'
        return key[:6] + '*' * (min(len(key) - 10, 6)) + key[-4:]

    @staticmethod
    def mask_sensitive_in_text(text: str) -> str:
        if not text:
            return text
        text = re.sub(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                      lambda m: DataMasker.mask_email(m.group(0)), text)
        text = re.sub(r'sk-[a-zA-Z0-9]{8,}',
                      lambda m: DataMasker.mask_api_key(m.group(0)), text)
        return text


class AuditLogger:
    """安全审计日志"""
    _LOG_DIR = "security_logs"
    _log_buffer: List[str] = []
    _MAX_BUFFER = 50

    def __init__(self):
        os.makedirs(self._LOG_DIR, exist_ok=True)

    @classmethod
    def _get_log_path(cls) -> str:
        return os.path.join(cls._LOG_DIR, f"audit_{datetime.now().strftime('%Y%m%d')}.log")

    @classmethod
    def log(cls, event_type: str, details: str, severity: str = "INFO") -> None:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        entry = f"[{timestamp}] [{severity}] [{event_type}] {details}\n"
        cls._log_buffer.append(entry)
        if len(cls._log_buffer) >= cls._MAX_BUFFER:
            cls._flush()

    @classmethod
    def _flush(cls) -> None:
        if not cls._log_buffer:
            return
        try:
            with open(cls._get_log_path(), 'a', encoding='utf-8') as f:
                f.writelines(cls._log_buffer)
            cls._log_buffer.clear()
        except Exception:
            pass

    @classmethod
    def get_recent_events(cls, count: int = 20) -> List[str]:
        cls._flush()
        try:
            log_path = cls._get_log_path()
            if os.path.exists(log_path):
                with open(log_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                return lines[-count:]
        except Exception:
            pass
        return []

    @classmethod
    def cleanup_old_logs(cls, days: int = 30) -> int:
        cls._flush()
        removed = 0
        cutoff = datetime.now() - timedelta(days=days)
        try:
            for fname in os.listdir(cls._LOG_DIR):
                if fname.startswith('audit_') and fname.endswith('.log'):
                    fpath = os.path.join(cls._LOG_DIR, fname)
                    try:
                        date_str = fname[6:14]
                        file_date = datetime.strptime(date_str, '%Y%m%d')
                        if file_date < cutoff:
                            os.remove(fpath)
                            removed += 1
                    except (ValueError, OSError):
                        pass
        except Exception:
            pass
        return removed


class TokenBucketRateLimiter:
    """Token Bucket 速率限制器"""
    def __init__(self):
        self._buckets: Dict[str, Dict[str, Any]] = {}
        self._ban_list: Dict[str, float] = {}

    def _cleanup_expired(self) -> None:
        now = time.time()
        for k in [k for k, v in self._buckets.items() if v.get('last_reset', 0) < now - 3600]:
            del self._buckets[k]
        for k in [k for k, v in self._ban_list.items() if v < now]:
            del self._ban_list[k]

    def check_rate(self, key: str, rate: float = 10.0, capacity: float = 20.0,
                   interval: float = 1.0) -> Tuple[bool, float]:
        now = time.time()
        self._cleanup_expired()
        if key in self._ban_list and self._ban_list[key] > now:
            return False, 0.0
        if key not in self._buckets:
            self._buckets[key] = {'tokens': capacity, 'last_refill': now, 'last_reset': now, 'violations': 0}
        bucket = self._buckets[key]
        elapsed = now - bucket['last_refill']
        bucket['tokens'] = min(capacity, bucket['tokens'] + elapsed * rate)
        bucket['last_refill'] = now
        if bucket['tokens'] >= 1.0:
            bucket['tokens'] -= 1.0
            bucket['violations'] = max(0, bucket['violations'] - 1)
            return True, bucket['tokens']
        else:
            bucket['violations'] += 1
            if bucket['violations'] > 20:
                self._ban_list[key] = now + 300
                AuditLogger.log("RATE_LIMIT_BAN", f"Key banned for 5min", "WARNING")
            return False, 0.0

    def get_remaining(self, key: str) -> float:
        if key in self._buckets:
            return self._buckets[key].get('tokens', 0)
        return 0.0


class SessionGuard:
    """会话安全"""
    _sessions: Dict[str, Dict[str, Any]] = {}
    _SESSION_TIMEOUT = 3600

    @classmethod
    def create_session(cls, client_ip: str = "unknown") -> str:
        cls._cleanup_expired()
        session_id = secrets.token_hex(32)
        csrf_token = secrets.token_hex(16)
        cls._sessions[session_id] = {
            'created_at': time.time(), 'last_activity': time.time(),
            'csrf_token': csrf_token, 'client_ip': client_ip,
            'request_count': 0,
        }
        AuditLogger.log("SESSION_CREATE", f"Session created: {session_id[:8]}...")
        return session_id

    @classmethod
    def validate_session(cls, session_id: str, csrf_token: Optional[str] = None) -> bool:
        cls._cleanup_expired()
        if session_id not in cls._sessions:
            return False
        session = cls._sessions[session_id]
        session['last_activity'] = time.time()
        session['request_count'] += 1
        if csrf_token and session['csrf_token'] != csrf_token:
            AuditLogger.log("CSRF_VIOLATION", "CSRF token mismatch", "WARNING")
            return False
        return True

    @classmethod
    def get_csrf_token(cls, session_id: str) -> Optional[str]:
        return cls._sessions.get(session_id, {}).get('csrf_token')

    @classmethod
    def _cleanup_expired(cls) -> None:
        now = time.time()
        expired = [sid for sid, s in cls._sessions.items() if now - s['last_activity'] > cls._SESSION_TIMEOUT]
        for sid in expired:
            del cls._sessions[sid]

    @classmethod
    def destroy_session(cls, session_id: str) -> None:
        if session_id in cls._sessions:
            del cls._sessions[session_id]


class EmailSecurityGuard:
    """邮件发送安全守卫"""
    _daily_counts: Dict[str, int] = {}
    _last_send_time: Dict[str, float] = {}
    _reset_day: str = datetime.now().strftime('%Y%m%d')
    MAX_EMAILS_PER_DAY = 200
    MIN_INTERVAL_SECONDS = 1.0
    MAX_RECIPIENTS = 50

    @classmethod
    def validate_send(cls, sender_key: str, recipient_count: int = 1) -> Tuple[bool, str]:
        today = datetime.now().strftime('%Y%m%d')
        if today != cls._reset_day:
            cls._daily_counts.clear()
            cls._reset_day = today
        current_count = cls._daily_counts.get(sender_key, 0)
        if current_count + recipient_count > cls.MAX_EMAILS_PER_DAY:
            return False, f"超出每日发送上限 ({cls.MAX_EMAILS_PER_DAY}封/天)"
        last_time = cls._last_send_time.get(sender_key, 0)
        elapsed = time.time() - last_time
        if elapsed < cls.MIN_INTERVAL_SECONDS:
            return False, f"发送过快，请等待 {cls.MIN_INTERVAL_SECONDS - elapsed:.1f} 秒"
        if recipient_count > cls.MAX_RECIPIENTS:
            return False, f"单次收件人过多 (最多{cls.MAX_RECIPIENTS}人)"
        return True, "OK"

    @classmethod
    def record_send(cls, sender_key: str, count: int = 1) -> None:
        cls._daily_counts[sender_key] = cls._daily_counts.get(sender_key, 0) + count
        cls._last_send_time[sender_key] = time.time()


class FileSecurityGuard:
    """文件上传安全验证"""
    ALLOWED_EXTENSIONS = {'.txt', '.csv', '.xlsx', '.xls', '.json'}
    MAX_FILE_SIZE = 10 * 1024 * 1024

    @classmethod
    def validate_file(cls, filename: str, file_data: bytes) -> Tuple[bool, str]:
        safe_name = InputSanitizer.sanitize_filename(filename)
        if safe_name != filename:
            return False, "文件名包含非法字符"
        ext = Path(filename).suffix.lower()
        if ext not in cls.ALLOWED_EXTENSIONS:
            return False, f"不支持的文件类型: {ext}，请使用 .csv 或 .xlsx"
        if len(file_data) == 0:
            return False, "文件为空"
        if len(file_data) > cls.MAX_FILE_SIZE:
            return False, f"文件过大 (最大{cls.MAX_FILE_SIZE // 1024 // 1024}MB)"
        return True, "OK"


class SecurityManager:
    """统一安全管理器"""
    def __init__(self):
        self.rate_limiter = TokenBucketRateLimiter()
        self.audit_logger = AuditLogger()
        self._initialized = False

    def initialize(self) -> None:
        if self._initialized:
            return
        AuditLogger.log("SECURITY_INIT", "Security module initialized")
        AuditLogger.cleanup_old_logs(30)
        SessionGuard._cleanup_expired()
        self._initialized = True

    def check_request_rate(self, client_key: str) -> Tuple[bool, str]:
        ok, _ = self.rate_limiter.check_rate("global", rate=50.0, capacity=100.0)
        if not ok:
            return False, "系统繁忙，请稍后再试"
        ok, _ = self.rate_limiter.check_rate(f"ip:{client_key}", rate=10.0, capacity=20.0)
        if not ok:
            return False, "请求过于频繁，请等待片刻"
        ok, _ = self.rate_limiter.check_rate(f"endpoint:{client_key}:generate", rate=5.0, capacity=10.0)
        if not ok:
            return False, "邮件生成请求过于频繁"
        return True, "OK"

    def sanitize_user_input(self, text: str, field_name: str = "unknown") -> str:
        clean_text, warnings = InputSanitizer.sanitize_input(text)
        for w in warnings:
            AuditLogger.log("INPUT_WARNING", f"[{field_name}] {w}", "WARNING")
        return clean_text

    def validate_send(self, sender_key: str, count: int = 1) -> Tuple[bool, str]:
        return EmailSecurityGuard.validate_send(sender_key, count)

    def record_send(self, sender_key: str, count: int = 1) -> None:
        EmailSecurityGuard.record_send(sender_key, count)
        AuditLogger.log("EMAIL_SENT", f"Email sent by {DataMasker.mask_email(sender_key)} (count={count})")


_security = SecurityManager()


# ============================================================================
# ====================== 🔧 配置层 (Configuration) ==========================
# ============================================================================

class AppConfig:
    """全局配置类（敏感值从环境变量/Streamlit Secrets加载，不硬编码）"""
    # ⚠️ 以下字段使用 _get_secret() 动态读取，禁止在此硬编码真实值
    _API_KEY: str = ""
    _BASE_URL: str = "https://dashscope.aliyuncs.com/compatible-mode/v1"
    _MODEL_NAME: str = "qwen-plus"

    @classmethod
    def _init_from_env(cls):
        """从环境变量 / Streamlit Secrets 加载配置（首次调用时自动执行）"""
        if not cls._API_KEY:
            cls._API_KEY = _get_secret("AI_EMAIL_API_KEY")
        if cls._BASE_URL == "https://dashscope.aliyuncs.com/compatible-mode/v1":
            cls._BASE_URL = _get_secret("AI_EMAIL_BASE_URL", cls._BASE_URL)
        if cls._MODEL_NAME == "qwen-plus":
            cls._MODEL_NAME = _get_secret("AI_EMAIL_MODEL_NAME", cls._MODEL_NAME)

    # SMTP 配置 (邮件发送)
    SMTP_HOST: str = ""
    SMTP_PORT: int = 465
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""  # 授权码，不是登录密码
    SENDER_EMAIL: str = ""
    SENDER_NAME: str = ""

    HISTORY_FILE: str = "email_history.json"
    TEMPLATES_FILE: str = "custom_templates.json"
    ENCRYPTED_CONFIG_FILE: str = ".encrypted_config.json"

    @classmethod
    def get_api_key(cls) -> str:
        """获取 API Key（环境变量 > 加密文件 > 报错提示用户配置）"""
        cls._init_from_env()
        if cls._API_KEY:
            return cls._API_KEY
        env_key = os.environ.get('AI_EMAIL_API_KEY', '')
        if env_key:
            return env_key
        encrypted_key = cls._load_encrypted_key()
        if encrypted_key:
            return encrypted_key
        # 不再硬编码兜底，提示用户配置
        raise ValueError(
            "❌ 未配置 AI API Key！请设置环境变量 AI_EMAIL_API_KEY 或在 Streamlit Cloud 中配置 Secrets"
        )

    @classmethod
    def get_base_url(cls) -> str:
        cls._init_from_env()
        return cls._BASE_URL

    @classmethod
    def get_model_name(cls) -> str:
        cls._init_from_env()
        return cls._MODEL_NAME

    @classmethod
    def _load_encrypted_key(cls) -> Optional[str]:
        try:
            if os.path.exists(cls.ENCRYPTED_CONFIG_FILE):
                with open(cls.ENCRYPTED_CONFIG_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                encrypted = data.get('api_key', '')
                if encrypted:
                    return CryptoVault.decrypt(encrypted)
        except Exception:
            pass
        return None

    @classmethod
    def save_encrypted_config(cls, api_key: str, smtp_password: str = "") -> bool:
        try:
            config = {}
            if api_key:
                config['api_key'] = CryptoVault.encrypt(api_key)
            if smtp_password:
                config['smtp_password'] = CryptoVault.encrypt(smtp_password)
            config['saved_at'] = datetime.now().isoformat()
            with open(cls.ENCRYPTED_CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
            AuditLogger.log("CONFIG_SAVED", "Encrypted config saved successfully")
            return True
        except Exception as e:
            AuditLogger.log("CONFIG_ERROR", f"Failed to save: {e}", "ERROR")
            return False

    @classmethod
    def get_masked_api_key(cls) -> str:
        return DataMasker.mask_api_key(cls.get_api_key())

    @classmethod
    def get_smtp_config(cls) -> Dict[str, Any]:
        return {
            'host': cls.SMTP_HOST,
            'port': cls.SMTP_PORT,
            'user': cls.SMTP_USER,
            'password': cls.SMTP_PASSWORD,
            'sender_email': cls.SENDER_EMAIL,
            'sender_name': cls.SENDER_NAME,
        }


# ============================================================================
# ====================== 📦 数据层 (Data Layer) =============================
# ============================================================================

COUNTRY_STYLES: Dict[str, str] = {
    "🇺🇸 美国": "Direct, concise, results-driven. Get straight to the point with concrete data. Avoid lengthy pleasantries.",
    "🇬🇧 英国": "Formal, polite, precise. Use standard British business English. Mind grammar and spelling (e.g. organisation, colour).",
    "🇩🇪 德国": "Extremely thorough, detail-oriented, logically structured. Must include accurate technical specs and data. No fluff.",
    "🇫🇷 法国": "Elegant, polite, slightly warm. Brief pleasantry before business. Use formal 'vous'.",
    "🇮🇹 意大利": "Warm, direct, relationship-focused. Emphasize aesthetics and craftsmanship of the product.",
    "🇪🇸 西班牙": "Warm, friendly, slightly relaxed pace. Use courteous phrases generously.",
    "🇦🇪 阿联酋(迪拜)": "Extremely polite, respect hierarchy. Build personal rapport before discussing business.",
    "🇸🇦 沙特阿拉伯": "Very formal, conservative, respect religious customs. Use honorific language.",
    "🇯🇵 日本": "Excessively polite, humble, etiquette-focused. Use keigo (honorific language) throughout.",
    "🇰🇷 韩国": "Formal, respect hierarchy, age/seniority matters. Use formal speech levels.",
    "🇸🇬 新加坡": "Efficient, pragmatic, blend of East meets West. Straight to business but friendly.",
    "🇮🇳 印度": "Warm, conversational, very price-conscious. Expect multiple follow-ups needed.",
    "🇧🇷 巴西": "Outgoing, relationship-first, relaxed and friendly tone.",
    "🇷🇺 俄罗斯": "Direct, decisive, confidence-inspiring. Firm and assertive tone.",
    "🇦🇺 澳大利亚": "Relaxed, casual, friendly. Communicate like a mate — professional but approachable.",
}

# Country -> Target Language mapping for AI output
LANGUAGE_MAP: Dict[str, str] = {
    "🇺🇸 美国": "American English",
    "🇬🇧 英国": "British English",
    "🇩🇪 德国": "German",
    "🇫🇷 法国": "French",
    "🇮🇹 意大利": "Italian",
    "🇪🇸 西班牙": "Spanish",
    "🇦🇪 阿联酋(迪拜)": "English (international business standard)",
    "🇸🇦 沙特阿拉伯": "English (international business standard)",
    "🇯🇵 日本": "English (international business standard)",
    "🇰🇷 韩国": "English (international business standard)",
    "🇸🇬 新加坡": "English (international business standard)",
    "🇮🇳 印度": "English (international business standard)",
    "🇧🇷 巴西": "English (international business standard)",
    "🇷🇺 俄罗斯": "English (international business standard)",
    "🇦🇺 澳大利亚": "Australian English",
}

EMAIL_SCENARIOS: Dict[str, str] = {
    "📩 首次开发信": "写一封高转化的首次开发信，不要太长，突出1-2个核心优势",
    "📨 二次跟进开发信": "跟进之前发过的开发信，提醒客户，补充新信息",
    "📬 三次跟进开发信": "第三次跟进，提供有价值的行业信息，建立信任",
    "💬 询盘快速回复": "及时回复客户的询盘，准确回答所有问题",
    "📊 报价单发送": "发送正式报价单，解释价格构成，强调性价比",
    "💰 催付定金": "礼貌地催促客户支付定金，确认订单细节",
    "📦 订单确认通知": "确认收到定金，告知订单已开始生产",
    "🚚 发货通知": "告知客户货物已发出，提供运单号和物流查询链接",
    "📬 到货提醒": "提醒客户货物即将到达，提醒准备清关资料",
    "💵 催付尾款": "礼貌地催促支付尾款，告知货物已到港",
    "🔧 售后问题处理": "处理售后投诉，先道歉再给方案",
    "🎁 样品申请回复": "回复样品申请，说明政策和交付时间",
    "🎉 节日问候": "节日问候，维护关系，不附带销售信息",
    "🎂 客户生日祝福": "生日祝福，建立个人联系",
    "📈 新品推荐": "向老客户推荐新产品，强调专属优惠",
    "📉 促销活动通知": "通知促销活动，制造紧迫感",
    "🤝 老客户回访": "回访老客户，了解产品使用情况",
    "❌ 订单取消处理": "处理取消请求，尽量挽回损失",
    "📝 合同签订跟进": "跟进签订合同，解答疑问",
    "🌐 展会邀请": "邀请参加展会，告知展位号和时间",
}

EMAIL_TONES: Dict[str, str] = {
    "💼 非常正式": "Highly formal executive tone. Use sophisticated vocabulary. Suitable for C-level executives.",
    "📝 标准商务": "Standard professional business tone. Polite, clear, suitable for most situations.",
    "😊 友好亲切": "Warm and friendly but still professional. Suitable for existing customers with prior contact.",
    "⚡ 简洁高效": "Ultra-concise. Only the essential points. No filler. For busy decision-makers.",
}


class DataManager:
    """数据管理层"""
    @staticmethod
    def load_history(file_path: str) -> List[Dict[str, Any]]:
        if os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                AuditLogger.log("DATA_ERROR", f"Failed to load history: {e}", "ERROR")
        return []

    @staticmethod
    def save_history(file_path: str, history: List[Dict[str, Any]]) -> None:
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(history, f, ensure_ascii=False, indent=2)
        except IOError as e:
            AuditLogger.log("DATA_ERROR", f"Failed to save history: {e}", "ERROR")

    @staticmethod
    def load_custom_templates(file_path: str) -> List[Dict[str, Any]]:
        if os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        return []


# ============================================================================
# ====================== 🤖 AI引擎层 (AI Engine) ============================
# ============================================================================

class PromptEngineer:
    """Prompt Engineering System — Professional foreign trade email generation"""

    # Scenario descriptions in English for the AI
    SCENARIO_MAP: Dict[str, str] = {
        "首次开发信": "first cold outreach email — introduce your company and product, highlight 1-2 core advantages, keep it short and compelling",
        "二次跟进开发信": "second follow-up to a previous email — gently remind the customer, add NEW valuable information",
        "三次跟进开发信": "third follow-up — provide genuine industry insight or value to build trust before selling",
        "询盘快速回复": "quick response to a customer inquiry — answer ALL questions thoroughly and professionally",
        "报价单发送": "formal quotation email — explain price breakdown, emphasize value-for-money and ROI",
        "催付定金": "polite payment reminder for deposit — confirm order details while requesting payment",
        "订单确认通知": "deposit received confirmation — inform that production has started",
        "发货通知": "shipment notification — provide tracking number and logistics info",
        "到货提醒": "arrival reminder — alert customer goods are arriving soon, remind about customs docs",
        "催付尾款": "balance payment reminder — politely request final payment, note goods have arrived",
        "售后问题处理": "after-sales complaint handling — apologize sincerely first, then present solution",
        "样品申请回复": "sample request response — explain sample policy and delivery timeline",
        "节日问候": "holiday greeting — relationship maintenance only, NO sales pitch",
        "客户生日祝福": "birthday wish — build personal connection with the customer",
        "新品推荐": "new product recommendation to existing customers — emphasize exclusive benefits",
        "促销活动通知": "promotion announcement — create urgency with clear deadline and offer",
        "老客户回访": "existing customer check-in — ask about product satisfaction, explore new needs",
        "订单取消处理": "order cancellation handling — try to save the sale, offer alternatives",
        "合同签订跟进": "contract signing follow-up — address concerns, move toward closing",
        "展会邀请": "trade show invitation — include booth number, date, and reason to visit",
    }

    @staticmethod
    def _detect_chinese(text: str) -> bool:
        """Detect if text contains Chinese characters"""
        for char in text:
            if '\u4e00' <= char <= '\u9fff':
                return True
        return False

    @staticmethod
    def build_prompt(
        country: str, scenario: str, tone: str,
        client_name: str, client_company: str,
        product_name: str, core_advantages: str,
        additional_info: str, email_length: int,
        signature: str, include_signature: bool,
    ) -> str:
        # Sanitize all inputs
        client_name = _security.sanitize_user_input(client_name, "client_name")
        client_company = _security.sanitize_user_input(client_company, "client_company")
        product_name = _security.sanitize_user_input(product_name, "product_name")
        core_advantages = _security.sanitize_user_input(core_advantages, "core_advantages")
        additional_info = _security.sanitize_user_input(additional_info, "additional_info")

        # Resolve target language
        target_lang = LANGUAGE_MAP.get(country, "English")

        # Resolve scenario description (extract Chinese part after emoji+space)
        scenario_key = scenario.split(" ", 1)[-1] if " " in scenario else scenario
        scenario_desc = PromptEngineer.SCENARIO_MAP.get(scenario_key, f"professional {scenario_key} email")

        # Resolve tone description
        tone_desc = EMAIL_TONES.get(tone, "Standard professional business tone")

        # Resolve country style
        country_style = COUNTRY_STYLES.get(country, "Standard international business style")

        # Detect if user input contains Chinese — if so, add translation instruction
        chinese_inputs = []
        if PromptEngineer._detect_chinese(product_name):
            chinese_inputs.append(f"product name (original: '{product_name}')")
        if PromptEngineer._detect_chinese(core_advantages):
            chinese_inputs.append(f"core advantages (original: '{core_advantages}')")
        if PromptEngineer._detect_chinese(client_company):
            chinese_inputs.append(f"company name (original: '{client_company}')")
        if PromptEngineer._detect_chinese(additional_info):
            chinese_inputs.append(f"additional info (original: '{additional_info}')")

        translation_note = ""
        if chinese_inputs:
            translation_note = f"""

# ⚠️ CRITICAL: LANGUAGE TRANSLATION REQUIRED
The user has provided input in Chinese for the following fields: {', '.join(chinese_inputs)}.
You MUST:
1. Translate ALL Chinese content into {target_lang} in the final email
2. Do NOT leave any Chinese characters in the output email
3. Adapt the translated product/company names to sound natural in {target_lang} business context
"""

        sig_block = f"\n\n# Signature\nAppend this signature at the end of the email:\n---\n{signature}\n---" if include_signature else ""

        return f"""# ROLE
You are a senior international trade director with 20 years of experience. You have successfully closed deals worth $50M+ across 100+ countries. You write emails that ACTUALLY get replies — not template garbage.

# TASK
Write a HIGH-CONVERSION {scenario_desc}.

# TARGET LANGUAGE (ABSOLUTE MANDATORY — MOST IMPORTANT RULE)
You MUST write the ENTIRE email in **{target_lang}**.
This is a NON-NEGOTIABLE requirement. The output must contain ZERO Chinese characters.
Every sentence, every word, must be in {target_lang}.{translation_note}

# CUSTOMER INFO
- Name: {client_name}
- Company: {client_company}
- Target Country/Region: {country}

# PRODUCT INFO
- Product: {product_name}
- Core Advantages:
{core_advantages}
- Additional Notes: {additional_info}

# WRITING RULES (FOLLOW ALL STRICTLY)
1. **Business Style**: {country_style}
2. **Tone**: {tone_desc}
3. **Length**: Keep the email body around {email_length} words (strict limit)
4. **NO AI-sounding templates**: Write like a REAL human. Avoid phrases like "I hope this email finds you well", "I am writing to introduce", "Please do not hesitate", "Looking forward to hearing from you". Instead use natural, conversational business language.
5. **Focus on BENEFITS not features**: Explain what the customer GAINS from your product
6. **Clear Call-to-Action**: End with a specific, natural next step — no generic closings
7. **NO emojis, NO special characters** in the email body
8. **Subject Line**: Include a compelling subject line at the very top (on its own line, prefixed with "Subject: ")
9. **Professional email structure**: Salutation → Opening hook → Value proposition → Social proof/details → CTA → Close{sig_block}

# OUTPUT FORMAT
Output ONLY the finished email ready to send. No explanations, no meta-commentary, no markdown formatting around it."""


class AIEngine:
    """AI生成引擎"""
    def __init__(self, config: type[AppConfig]):
        self.config = config
        self.client = OpenAI(
            api_key=config.get_api_key(),
            base_url=config.get_base_url(),
        )

    def generate_email(self, prompt: str, temperature: float = 0.6) -> str:
        api_key_hash = hashlib.sha256(self.config.get_api_key().encode()).hexdigest()[:16]
        ok, msg = _security.check_request_rate(f"ai:{api_key_hash}")
        if not ok:
            return f"请求过于频繁，请稍候再试。（安全限制: {msg}）"
        try:
            response = self.client.chat.completions.create(
                model=self.config.get_model_name(),
                messages=[{"role": "user", "content": prompt}],
                temperature=temperature,
                max_tokens=1500,
                top_p=0.9,
            )
            raw_content = response.choices[0].message.content
            result = raw_content.strip() if raw_content else ""
            AuditLogger.log("AI_GENERATE", f"Email generated ({len(result)} chars)")
            return result
        except Exception as e:
            error_msg = f"生成失败：{str(e)}"
            AuditLogger.log("AI_ERROR", f"Generation failed: {e}", "ERROR")
            return error_msg

    def generate_batch_emails(self, prompts: List[Tuple[str, Dict]], temperature: float = 0.6,
                               progress_callback=None) -> List[Dict[str, Any]]:
        """批量生成邮件（群发核心）"""
        results = []
        total = len(prompts)
        for i, (prompt, meta) in enumerate(prompts):
            if progress_callback:
                progress_callback(i, total, f"正在生成第 {i+1}/{total} 封邮件: {meta.get('name', '')}")

            content = self.generate_email(prompt, temperature)
            results.append({
                'name': meta.get('name', ''),
                'email': meta.get('email', ''),
                'company': meta.get('company', ''),
                'content': content,
                'status': 'success' if not content.startswith('生成失败') else 'error',
                'sent': False,
                'sent_time': None,
            })
            time.sleep(0.3)  # 防止API限流
        return results


# ============================================================================
# ====================== 📧 群发模块 (Batch Send Module) =====================
# ============================================================================

class BatchEmailManager:
    """群发管理器 - 一键导入 / 批量生成 / 一键发送"""

    SUPPORTED_COLUMNS_NAME = ['name', '姓名', '客户姓名', '客户名字', 'name_en', '英文名',
                              'email', '邮箱', '邮件', 'mail', 'email地址', 'Email',
                              'company', '公司', '公司名称', '公司名', 'Company']

    MAX_RECIPIENTS_PER_BATCH: int = 50

    def __init__(self, ai_engine: AIEngine, config: type[AppConfig]):
        self.ai_engine = ai_engine
        self.config = config
        self.contacts_df: Optional[pd.DataFrame] = None
        self.generated_emails: List[Dict[str, Any]] = []
        self.send_results: List[Dict[str, Any]] = []
        self.batch_progress: int = 0
        self.batch_status: str = "就绪"

    def import_contacts_from_file(self, uploaded_file) -> Tuple[int, str, pd.DataFrame]:
        """
        一键导入客户列表
        支持 .csv 和 .xlsx 文件
        自动识别列: 姓名/Name, 邮箱/Email, 公司/Company
        """
        try:
            file_data = uploaded_file.read()
            filename = uploaded_file.name

            # 文件安全验证
            ok, msg = FileSecurityGuard.validate_file(filename, file_data)
            if not ok:
                return 0, msg, pd.DataFrame()

            # 读取文件
            file_ext = Path(filename).suffix.lower()
            if file_ext in ('.xlsx', '.xls'):
                df = pd.read_excel(BytesIO(file_data))
            elif file_ext == '.csv':
                df = pd.read_csv(BytesIO(file_data), encoding='utf-8-sig')
            else:
                return 0, f"不支持的文件格式: {file_ext}", pd.DataFrame()

            if df.empty:
                return 0, "文件为空或无有效数据", pd.DataFrame()

            # 标准化列名映射
            column_map = {}
            for col in df.columns:
                col_lower = str(col).strip().lower()
                col_clean = str(col).strip()
                if col_lower in [c.lower() for c in self.SUPPORTED_COLUMNS_NAME]:
                    # 找到对应的标准化名称
                    for std_name in self.SUPPORTED_COLUMNS_NAME:
                        if col_lower == std_name.lower():
                            column_map[col] = std_name
                            break

            if not column_map:
                return 0, "未找到有效的列！需要包含: 姓名(name)、邮箱(email)、公司(company)", df.head()

            df = df.rename(columns=column_map)

            # 确保关键列存在
            name_col = None
            email_col = None
            company_col = None

            for possible_name in ['name', '姓名', '客户姓名', '客户名字', 'name_en', '英文名']:
                if possible_name in df.columns:
                    name_col = possible_name
                    break
            for possible_email in ['email', '邮箱', '邮件', 'mail', 'email地址', 'Email']:
                if possible_email in df.columns:
                    email_col = possible_email
                    break
            for possible_company in ['company', '公司', '公司名称', '公司名', 'Company']:
                if possible_company in df.columns:
                    company_col = possible_company
                    break

            if not email_col:
                return 0, "缺少邮箱列！文件中必须包含 email/邮箱 列", df.head()

            # 清洗数据
            clean_rows = []
            for _, row in df.iterrows():
                name_val = str(row.get(name_col, '')).strip() if name_col and pd.notna(row.get(name_col)) else ''
                email_val = str(row.get(email_col, '')).strip() if email_col and pd.notna(row.get(email_col)) else ''
                company_val = str(row.get(company_col, '')).strip() if company_col and pd.notna(row.get(company_col)) else ''

                if not email_val:
                    continue

                # 验证邮箱格式
                email_val, is_valid = InputSanitizer.sanitize_email_address(email_val)
                if not is_valid:
                    continue

                if not name_val:
                    name_val = email_val.split('@')[0]

                clean_rows.append({
                    'name': name_val,
                    'email': email_val,
                    'company': company_val,
                })

            if not clean_rows:
                return 0, "没有找到有效的客户数据（邮箱格式不正确）", df.head()

            self.contacts_df = pd.DataFrame(clean_rows)
            count = len(self.contacts_df)
            AuditLogger.log("BATCH_IMPORT", f"Imported {count} contacts from {filename}")
            return count, f"成功导入 {count} 个联系人！", self.contacts_df

        except Exception as e:
            AuditLogger.log("BATCH_IMPORT_ERROR", str(e), "ERROR")
            return 0, f"导入失败: {str(e)}", pd.DataFrame()

    def prepare_batch_prompts(
        self,
        country: str, scenario: str, tone: str,
        product_name: str, core_advantages: str,
        additional_info: str, email_length: int,
        signature: str, include_signature: bool,
    ) -> List[Tuple[str, Dict]]:
        """为所有联系人准备提示词"""
        if self.contacts_df is None or self.contacts_df.empty:
            return []

        prompts = []
        for _, row in self.contacts_df.iterrows():
            prompt = PromptEngineer.build_prompt(
                country=country, scenario=scenario, tone=tone,
                client_name=row['name'],
                client_company=row['company'],
                product_name=product_name,
                core_advantages=core_advantages,
                additional_info=additional_info,
                email_length=email_length,
                signature=signature,
                include_signature=include_signature,
            )
            prompts.append((prompt, {
                'name': row['name'],
                'email': row['email'],
                'company': row['company'],
            }))

        return prompts

    def generate_all(self, country: str, scenario: str, tone: str,
                     product_name: str, core_advantages: str,
                     additional_info: str, email_length: int,
                     signature: str, include_signature: bool,
                     temperature: float, progress_bar=None) -> List[Dict[str, Any]]:
        """一键批量生成所有邮件"""
        prompts = self.prepare_batch_prompts(
            country, scenario, tone,
            product_name, core_advantages,
            additional_info, email_length,
            signature, include_signature,
        )
        if not prompts:
            return []

        def on_progress(current, total, message):
            if progress_bar:
                progress_bar.progress(current / total, text=message)
            self.batch_progress = int(current / total * 100)
            self.batch_status = message

        self.generated_emails = self.ai_engine.generate_batch_emails(
            prompts, temperature, progress_callback=on_progress
        )
        AuditLogger.log("BATCH_GENERATE", f"Generated {len(self.generated_emails)} emails")
        return self.generated_emails

    def send_all_emails(self, smtp_config: Dict[str, Any], progress_bar=None,
                        delay_seconds: float = 2.0) -> List[Dict[str, Any]]:
        """
        一键发送所有已生成的邮件
        通过SMTP协议发送真实邮件
        """
        if not self.generated_emails:
            return [{'status': 'error', 'message': '没有可发送的邮件，先生成邮件'}]

        # SMTP连接检查
        if not smtp_config.get('host') or not smtp_config.get('user'):
            return [{'status': 'error', 'message': 'SMTP配置不完整，请在侧边栏配置邮件发送'}]

        results = []
        success_count = 0
        fail_count = 0
        total = len(self.generated_emails)

        # 安全验证
        session_key = st.session_state.get('session_id', 'unknown') if 'st' in sys.modules else 'unknown'
        ok, msg = _security.validate_send(session_key, total)
        if not ok:
            return [{'status': 'error', 'message': f'安全限制: {msg}'}]

        try:
            # 创建SMTP连接
            port = smtp_config.get('port', 465)
            if port == 465:
                # SSL连接
                server = smtplib.SMTP_SSL(smtp_config['host'], port, timeout=30)
            else:
                server = smtplib.SMTP(smtp_config['host'], port, timeout=30)
                server.starttls()

            server.login(smtp_config['user'], smtp_config['password'])

            for i, mail_item in enumerate(self.generated_emails):
                if progress_bar:
                    progress_bar.progress(i / total, text=f"正在发送第 {i+1}/{total} 封...")

                recipient_email = mail_item.get('email', '')
                recipient_name = mail_item.get('name', '')

                if not recipient_email:
                    results.append({'name': recipient_name, 'email': recipient_email,
                                    'status': 'skipped', 'message': '无收件人地址'})
                    fail_count += 1
                    continue

                # 构建邮件
                msg = MIMEMultipart('mixed')
                msg['From'] = f"{Header(smtp_config.get('sender_name', ''), 'utf-8').encode()} <{smtp_config.get('sender_email', smtp_config['user'])}>"
                msg['To'] = f"{Header(recipient_name, 'utf-8').encode()} <{recipient_email}>"
                msg['Subject'] = Header(scenario_to_subject(st.session_state.get('batch_scenario', '')), 'utf-8')

                # 正文
                body = mail_item.get('content', '')
                msg.attach(MIMEText(body, 'plain', 'utf-8'))

                # 发送
                try:
                    server.sendmail(smtp_config['sender_email'] or smtp_config['user'],
                                   [recipient_email], msg.as_string())
                    results.append({
                        'name': recipient_name, 'email': recipient_email,
                        'status': 'success', 'message': '发送成功',
                    })
                    success_count += 1
                    mail_item['sent'] = True
                    mail_item['sent_time'] = datetime.now().isoformat()
                    _security.record_send(session_key)
                    AuditLogger.log("EMAIL_SENT_OK", f"To: {DataMasker.mask_email(recipient_email)}")
                except smtplib.SMTPRecipientsRefused:
                    results.append({'name': recipient_name, 'email': recipient_email,
                                    'status': 'failed', 'message': '收件人地址被拒绝'})
                    fail_count += 1
                except smtplib.SMTPException as e:
                    results.append({'name': recipient_name, 'email': recipient_email,
                                    'status': 'failed', 'message': str(e)})
                    fail_count += 1

                # 发送间隔，防止被标记为垃圾邮件
                if i < total - 1:
                    time.sleep(delay_seconds)

            server.quit()

        except smtplib.SMTPAuthenticationError:
            results.append({'status': 'error', 'message': 'SMTP认证失败！检查用户名和授权码'})
        except smtplib.SMTPConnectError as e:
            results.append({'status': 'error', 'message': f'无法连接SMTP服务器: {e}'})
        except Exception as e:
            results.append({'status': 'error', 'message': f'发送过程出错: {e}'})

        if progress_bar:
            progress_bar.progress(1.0, text=f"发送完成! 成功:{success_count} 失败:{fail_count}")

        self.send_results = results
        AuditLogger.log("BATCH_SEND_COMPLETE", f"Sent {success_count}/{total}, failed {fail_count}")
        return results

    def get_contacts_preview(self, rows: int = 10) -> pd.DataFrame:
        if self.contacts_df is not None and not self.contacts_df.empty:
            return self.contacts_df.head(rows)
        return pd.DataFrame()

    def clear(self) -> None:
        self.contacts_df = None
        self.generated_emails = []
        self.send_results = []
        self.batch_progress = 0
        self.batch_status = "就绪"


def scenario_to_subject(scenario: str) -> str:
    """根据场景生成默认邮件主题"""
    mapping = {
        "首次开发信": "Business Cooperation Opportunity",
        "二次跟进开发信": "Following Up - Our Previous Discussion",
        "三次跟进开发信": "Quick Follow Up",
        "询盘快速回复": "Re: Your Inquiry",
        "报价单发送": "Quotation for Your Review",
        "催付定金": "Deposit Payment Reminder",
        "订单确认通知": "Order Confirmation",
        "发货通知": "Shipment Notification",
        "到货提醒": "Arrival Notice",
        "催付尾款": "Balance Payment Reminder",
        "售后问题处理": "Regarding Your Concern",
        "样品申请回复": "Sample Request Response",
        "节日问候": "Season's Greetings",
        "客户生日祝福": "Happy Birthday!",
        "新品推荐": "New Product Recommendation",
        "促销活动通知": "Special Promotion Alert",
        "老客户回访": "Customer Follow-up",
        "订单取消处理": "Order Cancellation Request",
        "合同签订跟进": "Contract Follow-up",
        "展会邀请": "Exhibition Invitation",
    }
    # 提取场景关键词
    for key in mapping:
        if key in scenario:
            return mapping[key]
    return "Business Email"


# ============================================================================
# ====================== 🛠️ 工具层 (Utilities) ==============================
# ============================================================================

class ExportUtils:
    """导出工具类"""

    @staticmethod
    def to_txt(content: str) -> BytesIO:
        return BytesIO(content.encode("utf-8"))

    @staticmethod
    def to_docx(content: str) -> BytesIO:
        doc = Document()
        doc.add_paragraph(content)
        buffer = BytesIO()
        doc.save(buffer)
        buffer.seek(0)
        return buffer

    @staticmethod
    def batch_to_csv(emails: List[Dict[str, Any]]) -> BytesIO:
        if not emails:
            return BytesIO(b'')
        df = pd.DataFrame([{
            '姓名': e.get('name', ''),
            '邮箱': e.get('email', ''),
            '公司': e.get('company', ''),
            '邮件内容': e.get('content', '')[:200] + ('...' if len(e.get('content', '')) > 200 else ''),
            '状态': e.get('status', ''),
            '是否发送': '是' if e.get('sent') else '否',
        } for e in emails])
        output = BytesIO()
        df.to_csv(output, index=False, encoding='utf-8-sig')
        output.seek(0)
        return output


# ============================================================================
# ====================== 🎨 界面层 (UI Layer) ===============================
# ============================================================================

class UIManager:
    """Streamlit界面管理 - 含群发功能"""

    def __init__(self, config: type[AppConfig], ai_engine: AIEngine):
        # ⚠️ set_page_config 必须在所有其他 Streamlit 命令之前调用
        st.set_page_config(
            page_title="AI外贸邮件生成器 Pro",
            page_icon="📧",
            layout="wide",
            initial_sidebar_state="expanded",
        )
        
        # 初始化认证会话
        AuthManager.init_session_state()
        
        # 隐藏 Streamlit Cloud 右下角 GitHub 头像（全局生效）
        st.markdown("""<style>
            .viewerBadge_container { display: none !important; }
            [data-testid="stAppViewBlockContainer"] [data-testid="stVerticalBlock"] > [data-testid="stVerticalBlock"] > [data-testid="stVerticalBlock"]:last-child { display: none !important; }
        </style>""", unsafe_allow_html=True)

        self.config = config
        self.ai_engine = ai_engine
        self.history = DataManager.load_history(config.HISTORY_FILE)
        self.batch_manager = BatchEmailManager(ai_engine, config)
        _security.initialize()

        if "session_id" not in st.session_state:
            client_ip = hashlib.sha256(str(time.time()).encode()).hexdigest()[:16]
            st.session_state.session_id = SessionGuard.create_session(client_ip)
            st.session_state.csrf_token = SessionGuard.get_csrf_token(st.session_state.session_id)
            AuditLogger.log("UI_SESSION", f"New session: {st.session_state.session_id[:8]}...")

    def render_sidebar(self) -> Dict[str, Any]:
        """渲染侧边栏"""
        with st.sidebar:
            # ---- 用户信息区 ----
            if AuthManager.is_authenticated():
                with st.container(border=True):
                    user_col1, user_col2 = st.columns([3, 1])
                    with user_col1:
                        st.markdown(f"👤 **{AuthManager.get_user_email()}**")
                        if AuthManager.is_admin():
                            st.caption("🛡️ 管理员")
                    with user_col2:
                        if st.button("🚪", help="退出登录"):
                            AuthManager.logout()
                            st.rerun()
                st.divider()
            
            st.header("⚙️ 邮件配置")

            country = st.selectbox("客户国家/地区", list(COUNTRY_STYLES.keys()), index=0)
            scenario = st.selectbox("邮件场景", list(EMAIL_SCENARIOS.keys()), index=0)
            tone = st.selectbox("邮件语气", list(EMAIL_TONES.keys()), index=1)

            st.subheader("高级设置")
            email_length = st.slider("邮件长度", 100, 600, 250, step=50)
            temperature = st.slider("创意度", 0.0, 1.0, 0.6, step=0.1,
                                     help="0=最严谨，1=最有创意，外贸推荐0.5-0.7")
            include_signature = st.checkbox("自动添加签名", value=True)
            signature = st.text_area(
                "你的签名",
                "Best regards,\n[你的名字]\n[你的职位]\n[公司名称]\n电话: [你的电话]\n邮箱: [你的邮箱]",
                height=120,
            )

            test_mode = st.checkbox("🔬 测试模式（不消耗API额度）", value=False)

            # ---- SMTP 邮件发送配置 ----
            st.divider()
            st.subheader("📧 邮件发送(SMTP)")
            smtp_host = st.text_input("SMTP服务器", placeholder="smtp.qiye.aliyun.com",
                                      value=self.config.SMTP_HOST, autocomplete="off")
            smtp_port = st.number_input("端口", value=self.config.SMTP_PORT, min_value=1, max_value=65535)
            smtp_user = st.text_input("SMTP账号/邮箱", value=self.config.SMTP_USER, autocomplete="off")
            smtp_password = st.text_input("授权码/密码", type="default",
                                          value=self.config.SMTP_PASSWORD, autocomplete="new-password")
            sender_email = st.text_input("发件人邮箱", value=self.config.SENDER_EMAIL, autocomplete="off")
            sender_name = st.text_input("发件人名称", value=self.config.SENDER_NAME, autocomplete="off")

            # 更新配置
            self.config.SMTP_HOST = smtp_host
            self.config.SMTP_PORT = int(smtp_port)
            self.config.SMTP_USER = smtp_user
            self.config.SMTP_PASSWORD = smtp_password
            self.config.SENDER_EMAIL = sender_email
            self.config.SENDER_NAME = sender_name

            # ---- 历史记录 ----
            st.divider()
            hist_row = st.container()
            with hist_row:
                hist_left, hist_right = st.columns([4, 1], gap="small")
                hist_left.markdown("**📜 历史记录**")
                if self.history:
                    hist_right.button("🗑 全部清除", key="clear_all_hist",
                                      use_container_width=True,
                                      on_click=lambda: (self.history.clear(),
                                                        DataManager.save_history(
                                                            self.config.HISTORY_FILE, []),
                                                        st.rerun()))

            if self.history:
                for i, item in enumerate(reversed(self.history[-5:])):
                    real_idx = len(self.history) - 1 - i  # 实际索引（从原列表倒序）
                    with st.container():
                        col_main, col_del = st.columns([10, 0.6], gap="small")
                        with col_main:
                            with st.expander(f"**{item['time']}** · {item['scenario']}", icon="💬"):
                                st.text_area("", item["content"], height=140,
                                             key=f"history_{i}", label_visibility="collapsed")
                                st.caption("点击上方标题可折叠/展开")
                        with col_del:
                            if st.button("🗑️", key=f"del_hist_{real_idx}",
                                         help="删除此条记录"):
                                self.history.pop(real_idx)
                                DataManager.save_history(self.config.HISTORY_FILE, self.history)
                                st.rerun()

                if len(self.history) > 5:
                    st.caption(f"仅显示最近 **5** 条，共 **{len(self.history)}** 条记录")
            else:
                st.info("暂无历史记录，生成邮件后会自动保存")

            return {
                "country": country, "scenario": scenario, "tone": tone,
                "email_length": email_length, "temperature": temperature,
                "include_signature": include_signature, "signature": signature,
                "test_mode": test_mode,
            }

    def render_main_content(self, sidebar_config: Dict[str, Any]) -> None:
        """主内容区 - 多Tab: 单封邮件 + 群发管理 + 管理后台(仅管理员)"""
        
        # 保险机制：如果已登录但 is_admin 未设置，从数据库重新读取
        if AuthManager.is_authenticated() and not st.session_state.get('is_admin', False):
            sb = get_supabase_client()
            if sb and st.session_state.get('user_id'):
                try:
                    profile = sb.table('user_profiles').select('is_admin').eq('id', st.session_state.user_id).execute()
                    if profile.data and profile.data[0].get('is_admin'):
                        st.session_state.is_admin = True
                except Exception:
                    pass
        
        # 根据权限构建Tab列表
        tabs = ["✉️ 单封邮件", "📨 群发管理"]
        if st.session_state.get('is_admin', False):
            tabs.append("🛡️ 管理后台")
        
        active_tab = st.session_state.get('active_tab', tabs[0])
        
        # 如果当前Tab不是第一个且存在，则更新
        if active_tab not in tabs:
            active_tab = tabs[0]
        
        selected = st.radio("📑 功能导航", tabs, index=tabs.index(active_tab), 
                           horizontal=True, label_visibility="collapsed")
        st.session_state.active_tab = selected
        
        # 渲染对应Tab内容
        if selected == "✉️ 单封邮件":
            self._render_single_email(sidebar_config)
        elif selected == "📨 群发管理":
            self._render_batch_module(sidebar_config)
        elif selected == "🛡️ 管理后台" and AuthManager.is_admin():
            self._render_admin_panel()

    def _render_single_email(self, sidebar_config: Dict[str, Any]):
        """单封邮件生成 + 发送"""
        st.title("📧 单封邮件")
        st.caption("填写客户信息 → AI 生成 → 一键发送")

        if "email_content" not in st.session_state:
            st.session_state.email_content = None

        col1, col2 = st.columns([1, 1])

        with col1:
            st.markdown("**📝 客户信息**")
            client_name = st.text_input("姓名 *", placeholder="John Smith")
            client_email = st.text_input("邮箱 *", placeholder="john@company.com")
            client_company = st.text_input("公司", placeholder="ABC Trading Co., Ltd.")

            st.divider()
            st.markdown("**📦 产品信息**")
            product_name = st.text_input("产品", placeholder="例如: 智能手机 / Solar LED Street Light")
            core_advantages = st.text_area(
                "核心优势",
                placeholder="1. CE认证  2. 价格优势15%  3. 7天交货",
                height=85,
            )
            additional_info = st.text_input(
                "补充信息（可选）",
                placeholder="促销/展会等",
            )

            generate_btn = st.button("✨ AI 生成邮件", type="primary", use_container_width=True)

        with col2:
            st.markdown("**✉️ 邮件预览**")

            if generate_btn:
                if not client_name:
                    st.error("请输入客户姓名！")
                    return
                if not client_email:
                    st.error("请输入客户邮箱！")
                    return

                # Session 自动修复
                session_id = st.session_state.get('session_id', '')
                csrf_token = st.session_state.get('csrf_token', '')
                if not SessionGuard.validate_session(session_id, csrf_token):
                    new_sid = SessionGuard.create_session("auto_recover")
                    st.session_state.session_id = new_sid
                    st.session_state.csrf_token = SessionGuard.get_csrf_token(new_sid)

                ok, rate_msg = _security.check_request_rate(st.session_state['session_id'])
                if not ok:
                    st.warning(f"⏳ {rate_msg}")
                    return

                with st.spinner("AI 正在生成…"):
                    if sidebar_config["test_mode"]:
                        # Test mode: generate a professional English mock email
                        target_lang = LANGUAGE_MAP.get(sidebar_config['country'], "English")
                        cn = sidebar_config['country'].split(' ', 1)[1] if ' ' in sidebar_config['country'] else sidebar_config['country']
                        # Translate Chinese product name to English for mock
                        mock_product = product_name
                        if PromptEngineer._detect_chinese(product_name):
                            mock_product = f"[{product_name} — {target_lang} translation needed]"
                        mock_advantages = core_advantages
                        if PromptEngineer._detect_chinese(core_advantages):
                            mock_advantages = f"[{core_advantages} — {target_lang} translation needed]"

                        st.session_state.email_content = (
                            f"Subject: Partnership Opportunity — {mock_product}\n\n"
                            f"Dear {client_name or 'There'},\n\n"
                            f"I hope this message finds you well. I'm reaching out from the international trade "
                            f"department to explore a potential collaboration regarding **{mock_product}**.\n\n"
                            f"Our product has gained significant traction in the {cn} market, and we believe it could "
                            f"bring substantial value to {client_company or 'your organization'}.\n\n"
                            f"**Key Advantages:**\n{mock_advantages}\n\n"
                            f"I'd welcome the opportunity to discuss how we can support your business goals. "
                            f"Are you available for a brief call this week?\n\n"
                            f"Best regards,\n"
                            f"{sidebar_config['signature'] if sidebar_config['include_signature'] else '[Your Name]'}\n"
                        )
                    else:
                        prompt = PromptEngineer.build_prompt(
                            country=sidebar_config["country"],
                            scenario=sidebar_config["scenario"],
                            tone=sidebar_config["tone"],
                            client_name=client_name,
                            client_company=client_company,
                            product_name=product_name,
                            core_advantages=core_advantages,
                            additional_info=additional_info,
                            email_length=sidebar_config["email_length"],
                            signature=sidebar_config["signature"],
                            include_signature=sidebar_config["include_signature"],
                        )
                        st.session_state.email_content = self.ai_engine.generate_email(
                            prompt, temperature=sidebar_config["temperature"]
                        )

                    self.history.append({
                        "time": datetime.now().strftime("%Y-%m-%d %H:%M"),
                        "scenario": sidebar_config["scenario"].split(" ")[1],
                        "content": st.session_state.email_content,
                    })
                    DataManager.save_history(self.config.HISTORY_FILE, self.history)
                    st.success("邮件已生成")

            # ---- 邮件内容显示 + 发送操作 ----
            if st.session_state.email_content is not None:
                st.text_area("", st.session_state.email_content, height=300, key="result",
                             label_visibility="collapsed")

                st.divider()

                # ---- 发送区 ----
                smtp_conf = self.config.get_smtp_config()
                smtp_ok = bool(smtp_conf.get('host') and smtp_conf.get('user'))

                send_col1, send_col2, send_col3 = st.columns([2, 2, 1])
                with send_col1:
                    send_btn = st.button(
                        "📤 发送邮件",
                        type="primary",
                        use_container_width=True,
                        disabled=(not smtp_ok),
                        help="未配置SMTP时不可用" if not smtp_ok else f"发送至: {client_email}",
                    )
                with send_col2:
                    st.download_button(label="💾 导出TXT",
                        data=ExportUtils.to_txt(st.session_state.email_content),
                        file_name=f"email_{datetime.now().strftime('%Y%m%d%H%M')}.txt",
                        mime="text/plain", use_container_width=True)
                with send_col3:
                    st.download_button(label="📄 导出Word",
                        data=ExportUtils.to_docx(st.session_state.email_content),
                        file_name=f"email_{datetime.now().strftime('%Y%m%d%H%M')}.docx",
                        mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        use_container_width=True)

                if not smtp_ok and st.session_state.email_content is not None:
                    st.caption("⚠️ 请在左侧栏配置 SMTP 后即可发送邮件")

                # 执行发送
                if send_btn:
                    if not client_email or '@' not in client_email:
                        st.error("请输入有效的收件人邮箱地址！")
                        return

                    try:
                        port = smtp_conf.get('port', 465)
                        if port == 465:
                            server = smtplib.SMTP_SSL(smtp_conf['host'], port, timeout=30)
                        else:
                            server = smtplib.SMTP(smtp_conf['host'], port, timeout=30)
                            server.starttls()

                        server.login(smtp_conf['user'], smtp_conf['password'])

                        msg = MIMEMultipart('mixed')
                        sender_display = smtp_conf.get('sender_name', '') or ''
                        sender_addr = smtp_conf.get('sender_email') or smtp_conf['user']
                        msg['From'] = f"{Header(sender_display, 'utf-8').encode()} <{sender_addr}>"
                        msg['To'] = f"{Header(client_name or '', 'utf-8').encode()} <{client_email}>"
                        subject = sidebar_config["scenario"].split(" ", 1)[-1] if " " in sidebar_config["scenario"] else "Business Email"
                        msg['Subject'] = Header(subject, 'utf-8')
                        msg.attach(MIMEText(st.session_state.email_content, 'plain', 'utf-8'))

                        server.sendmail(sender_addr, [client_email], msg.as_string())
                        server.quit()

                        st.success(f"✅ 已发送至 `{DataMasker.mask_email(client_email)}`")
                        st.balloons()
                        AuditLogger.log("SINGLE_EMAIL_SENT_OK", f"To: {DataMasker.mask_email(client_email)}")

                    except smtplib.SMTPAuthenticationError:
                        st.error("❌ SMTP 认证失败，检查账号和授权码")
                    except smtplib.SMTPConnectError as e:
                        st.error(f"❌ 连接 SMTP 服务器失败: {e}")
                    except Exception as e:
                        st.error(f"❌ 发送失败: {e}")

    def _render_batch_module(self, sidebar_config: Dict[str, Any]):
        """群发管理模块 - 专业版 UI"""
        # 保存群发场景
        st.session_state.batch_scenario = sidebar_config["scenario"]

        # ---- 顶部状态栏 ----
        has_contacts = self.batch_manager.contacts_df is not None and not self.batch_manager.contacts_df.empty
        has_emails = bool(self.batch_manager.generated_emails)
        contact_count = len(self.batch_manager.contacts_df) if has_contacts else 0
        email_count = len(self.batch_manager.generated_emails) if has_emails else 0
        sent_count = sum(1 for e in self.batch_manager.generated_emails if e.get('sent')) if has_emails else 0

        status_cols = st.columns(4)
        status_cols[0].metric(
            "📋 联系人", contact_count,
            delta=f"+{contact_count}" if contact_count > 0 else None,
            delta_color="normal"
        )
        status_cols[1].metric("✉️ 已生成", email_count)
        status_cols[2].metric("📤 已发送", sent_count)
        status_cols[3].metric(
            "⚡ 进度",
            f"{int(sent_count / email_count * 100)}%" if email_count > 0 else "0%",
            delta="就绪" if email_count == 0 else ("完成" if sent_count >= email_count else "进行中"),
            delta_color="off" if email_count == 0 else ("normal" if sent_count >= email_count else "normal")
        )

        st.divider()

        # ---- 三栏卡片布局：导入 | 生成 | 发送 ----
        card1, card2, card3 = st.columns(3, gap="medium")

        # ====================
        # 卡片1: 导入客户
        # ====================
        with card1:
            with st.container(border=True):
                st.markdown("#### 📥 导入客户")
                st.caption("Excel / CSV")

                uploaded_file = st.file_uploader(
                    "选择文件",
                    type=['csv', 'xlsx', 'xls'],
                    help="需包含 邮箱(Email) 列；可选 姓名(Name)、公司(Company)",
                    label_visibility="collapsed",
                )

                if uploaded_file:
                    count, msg, df_preview = self.batch_manager.import_contacts_from_file(uploaded_file)
                    if count > 0:
                        st.success(msg)
                    elif msg:
                        st.error(msg)

                if has_contacts:
                    st.caption(f"已加载 **{contact_count}** 人")
                    with st.popover("👁 查看列表", use_container_width=True):
                        st.dataframe(
                            self.batch_manager.contacts_df.head(20),
                            use_container_width=True,
                            hide_index=True,
                            height=300,
                        )
                        if contact_count > 20:
                            st.caption(f"…共 {contact_count} 条，仅显示前20")

        # ====================
        # 卡片2: AI 生成
        # ====================
        with card2:
            with st.container(border=True):
                st.markdown("#### 🤖 AI 批量生成")

                batch_product = st.text_input(
                    "产品", placeholder="太阳能LED路灯",
                    key="batch_product", label_visibility="collapsed"
                )
                batch_advantages = st.text_area(
                    "核心优势", placeholder="1. CE认证  2. 价格优势15%  3. 7天交货",
                    key="batch_advantages", height=80, label_visibility="collapsed"
                )
                batch_extra = st.text_input(
                    "补充", placeholder="促销/展会等（可选）",
                    key="batch_extra", label_visibility="collapsed"
                )

                gen_btn = st.button(
                    "⚡ 一键生成全部",
                    type="primary",
                    use_container_width=True,
                    disabled=not has_contacts,
                )

                if gen_btn:
                    progress = st.progress(0, text="生成中…")
                    with st.spinner(""):
                        results = self.batch_manager.generate_all(
                            country=sidebar_config["country"],
                            scenario=sidebar_config["scenario"],
                            tone=sidebar_config["tone"],
                            product_name=batch_product,
                            core_advantages=batch_advantages,
                            additional_info=batch_extra,
                            email_length=sidebar_config["email_length"],
                            signature=sidebar_config["signature"],
                            include_signature=sidebar_config["include_signature"],
                            temperature=sidebar_config["temperature"],
                            progress_bar=progress,
                        )
                    progress.empty()

                    ok = sum(1 for r in results if r['status'] == 'success')
                    err = sum(1 for r in results if r['status'] == 'error')
                    if err == 0:
                        st.success(f"全部 {ok} 封生成成功")
                    else:
                        st.warning(f"成功 {ok} · 失败 {err}")

                if has_emails:
                    st.caption(f"已生成 **{email_count}** 封")
                    if st.button("🗑 清空", use_container_width=True, key="clear_batch"):
                        self.batch_manager.clear()
                        st.rerun()

        # ====================
        # 卡片3: 批量发送
        # ====================
        with card3:
            with st.container(border=True):
                st.markdown("#### 📤 批量发送")

                smtp_conf = self.config.get_smtp_config()
                smtp_ready = bool(smtp_conf.get('host') and smtp_conf.get('user'))

                if smtp_ready:
                    st.caption(f"SMTP: `{smtp_conf['host']}` ✓")
                else:
                    st.caption("⚠ 请在左侧栏配置SMTP")

                send_delay = st.slider(
                    "间隔", 0.5, 10.0, 2.0, 0.5,
                    help="秒/封，防止垃圾邮件标记",
                    label_visibility="visible"
                )

                test_send = st.toggle("试发模式（仅发首封）", value=False)

                send_disabled = not has_emails or not smtp_ready
                send_btn = st.button(
                    "🚀 一键发送全部",
                    type="primary",
                    use_container_width=True,
                    disabled=send_disabled,
                )

                if send_btn:
                    # 非试发需确认
                    if not test_send:
                        st.session_state._send_confirm = True

                # 二次确认弹窗
                if st.session_state.get('_send_confirm') and not test_send:
                    with st.container(border=True):
                        st.warning(f"即将向 **{email_count}** 位客户发送邮件")
                        confirm_col1, confirm_col2 = st.columns(2)
                        if confirm_col1.button("✓ 确认发送", type="primary", use_container_width=True):
                            st.session_state._send_confirm = False
                            self._do_send(smtp_conf, send_delay, test_send=False)
                        if confirm_col2.button("✗ 取消", use_container_width=True):
                            st.session_state._send_confirm = False

                if send_btn and test_send:
                    self._do_send(smtp_conf, send_delay, test_send=True)

        # ---- 邮件列表（全宽） ----
        if has_emails:
            st.divider()

            # 快捷操作栏
            toolbar_col1, toolbar_col2, toolbar_col3, toolbar_col4 = st.columns([1, 1, 1, 3])
            with toolbar_col1:
                st.download_button(
                    "📥 导出CSV",
                    data=ExportUtils.batch_to_csv(self.batch_manager.generated_emails),
                    file_name=f"外贸邮件_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
                    mime="text/csv",
                    use_container_width=True,
                )
            with toolbar_col2:
                st.download_button(
                    "📄 导出TXT",
                    data=ExportUtils.to_txt(
                        "\n\n---\n\n".join(
                            f"To: {e['name']} <{e['email']}>\n\n{e['content']}"
                            for e in self.batch_manager.generated_emails
                        )
                    ),
                    file_name=f"外贸邮件_{datetime.now().strftime('%Y%m%d_%H%M')}.txt",
                    mime="text/plain",
                    use_container_width=True,
                )
            with toolbar_col3:
                pass  # 占位，保持平衡

            # 邮件卡片网格
            show_count = min(email_count, 50)
            st.caption(f"预览 {show_count}/{email_count} 封")

            for i, mail in enumerate(self.batch_manager.generated_emails[:show_count]):
                name = mail.get('name', '—')
                email_masked = DataMasker.mask_email(mail.get('email', ''))
                company = mail.get('company', '') or '—'
                is_ok = mail['status'] == 'success'
                is_sent = mail.get('sent', False)

                # 状态徽章
                badge = ""
                if is_sent:
                    badge = "🟢 已发送"
                elif is_ok:
                    badge = "🟡 待发送"
                else:
                    badge = "🔴 失败"

                label = f"#{i+1}  {name}  ·  {email_masked}  ·  {company}  {badge}"

                with st.expander(label):
                    st.text_area(
                        "邮件内容",
                        mail['content'],
                        height=200,
                        key=f"batch_preview_{i}",
                        label_visibility="collapsed",
                    )

            if email_count > show_count:
                st.caption(f"… 还有 {email_count - show_count} 封，请导出CSV查看全部")

            # ---- 发送结果区 ----
            if self.batch_manager.send_results:
                st.divider()
                st.markdown("#### 📊 发送报告")
                sr = self.batch_manager.send_results
                ok_s = sum(1 for r in sr if r.get('status') == 'success')
                fail_s = sum(1 for r in sr if r.get('status') == 'failed')
                skip_s = sum(1 for r in sr if r.get('status') == 'skipped')
                err_s = sum(1 for r in sr if r.get('status') == 'error')

                res_cols = st.columns(4)
                res_cols[0].metric("✅ 成功", ok_s)
                res_cols[1].metric("❌ 失败", fail_s)
                res_cols[2].metric("⏭ 跳过", skip_s)
                res_cols[3].metric("⚠ 错误", err_s)

                if ok_s > 0:
                    st.success(f"发送完成 — 成功 {ok_s} 封")
                    st.balloons()

    # ---- 提取发送逻辑 ----
    def _do_send(self, smtp_conf: dict, send_delay: float, test_send: bool):
        """执行邮件发送"""
        if test_send:
            original = self.batch_manager.generated_emails[:]
            self.batch_manager.generated_emails = [original[0]]
            progress_send = st.progress(0, text="试发…")
            send_results = self.batch_manager.send_all_emails(
                smtp_conf, progress_bar=progress_send, delay_seconds=send_delay
            )
            self.batch_manager.generated_emails = original
            progress_send.empty()
            self.batch_manager.send_results = send_results
        else:
            progress_send = st.progress(0, text="发送中…")
            send_results = self.batch_manager.send_all_emails(
                smtp_conf, progress_bar=progress_send, delay_seconds=send_delay
            )
            progress_send.empty()
            self.batch_manager.send_results = send_results

    # ---- 管理员面板 ----
    def _render_admin_panel(self):
        """🛡️ 管理员后台 - 用户管理"""
        st.title("🛡️ 管理后台")
        st.caption("管理所有注册用户，启用/禁用账号")
        
        sb = get_supabase_client()
        if not sb:
            st.error("❌ 无法连接 Supabase，请检查网络")
            return
        
        # 获取所有用户
        with st.spinner("加载用户列表..."):
            try:
                # 获取用户列表
                users_response = sb.auth.admin.list_users()
                all_users = users_response.users if hasattr(users_response, 'users') else []
                
                # 获取用户配置
                profiles_response = sb.table('user_profiles').select('*').execute()
                profiles = {p['id']: p for p in profiles_response.data}
            except Exception as e:
                st.error(f"获取用户列表失败: {str(e)}")
                return
        
        if not all_users:
            st.info("暂无注册用户")
            return
        
        # 统计信息
        total_users = len(all_users)
        active_users = sum(1 for u in all_users if u.email_confirmed_at)
        admin_count = sum(1 for p in profiles.values() if p.get('is_admin', False))
        
        stat_cols = st.columns(3)
        stat_cols[0].metric("👥 总用户", total_users)
        stat_cols[1].metric("✅ 已验证", active_users)
        stat_cols[2].metric("🛡️ 管理员", admin_count)
        
        st.divider()
        
        # 用户列表
        st.markdown("### 👥 用户列表")
        
        for user in all_users:
            profile = profiles.get(user.id, {})
            is_admin = profile.get('is_admin', False)
            is_active = user.email_confirmed_at is not None
            
            # 创建用户卡片
            with st.container(border=True):
                user_row1, user_row2, user_row3 = st.columns([3, 1, 1], gap="small")
                
                with user_row1:
                    status_icon = "✅" if is_active else "⏳"
                    admin_badge = " 🛡️" if is_admin else ""
                    st.markdown(f"**{status_icon} {user.email}**{admin_badge}")
                    st.caption(f"ID: {user.id[:8]}... | 注册: {user.created_at[:10] if user.created_at else '未知'}")
                    
                    # 使用统计
                    stats = profile.get('total_emails_generated', 0)
                    if stats > 0:
                        st.caption(f"📧 已生成 {stats} 封邮件")
                
                with user_row2:
                    # 设置管理员按钮
                    if is_admin:
                        if st.button("🔒 撤销管理", key=f"revoke_admin_{user.id[:8]}", use_container_width=True):
                            try:
                                sb.table('user_profiles').update({'is_admin': False}).eq('id', user.id).execute()
                                st.success("已撤销管理员权限")
                                st.rerun()
                            except Exception as e:
                                st.error(f"操作失败: {e}")
                    else:
                        if st.button("🛡️ 设为管理", key=f"set_admin_{user.id[:8]}", use_container_width=True):
                            try:
                                sb.table('user_profiles').update({'is_admin': True}).eq('id', user.id).execute()
                                st.success("已设置为管理员")
                                st.rerun()
                            except Exception as e:
                                st.error(f"操作失败: {e}")
                
                with user_row3:
                    # 禁用/启用按钮
                    if is_active:
                        if st.button("🚫 禁用账号", key=f"disable_{user.id[:8]}", use_container_width=True, type="secondary"):
                            try:
                                # 通过更新 is_active 字段来禁用
                                sb.table('user_profiles').update({'is_active': False}).eq('id', user.id).execute()
                                st.warning(f"已禁用 {user.email}")
                                st.rerun()
                            except Exception as e:
                                st.error(f"操作失败: {e}")
                    else:
                        if st.button("✅ 启用账号", key=f"enable_{user.id[:8]}", use_container_width=True, type="primary"):
                            try:
                                sb.table('user_profiles').update({'is_active': True}).eq('id', user.id).execute()
                                st.success(f"已启用 {user.email}")
                                st.rerun()
                            except Exception as e:
                                st.error(f"操作失败: {e}")
        
        st.divider()
        st.caption("💡 提示：管理员可以登录系统后台，禁用账号将阻止该用户登录")

    def run(self) -> None:
        """启动应用"""
        sidebar_config = self.render_sidebar()
        self.render_main_content(sidebar_config)


# ============================================================================
# ====================== 主程序入口 (Main Entry) =============================
# ============================================================================

def main() -> None:
    """AI外贸邮件生成器 Pro - 完整版 主入口"""
    
    # 初始化认证系统
    if not require_auth():
        return  # 未登录则停止
    
    # 初始化安全模块
    _security.initialize()
    
    # 记录登录用户
    if AuthManager.is_authenticated():
        AuditLogger.log("APP_START", f"User logged in: {AuthManager.get_user_email()}")
    
    AuditLogger.log("APP_START", "=" * 50)
    AuditLogger.log("APP_START", "AI Foreign Trade Email Generator Pro (Full Edition) started")
    AuditLogger.cleanup_old_logs(30)

    ai_engine = AIEngine(AppConfig)
    ui = UIManager(AppConfig, ai_engine)
    ui.run()

    AuditLogger._flush()


if __name__ == "__main__":
    main()
