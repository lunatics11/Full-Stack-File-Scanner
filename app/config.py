import os
from pathlib import Path

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
    UPLOAD_FOLDER = os.path.join(Path(__file__).parent.parent, 'static', 'uploads')
    MAX_CONTENT_LENGTH = 32 * 1024 * 1024  # Increased to 32MB (VT max)
    
    # VirusTotal Enhanced Configuration
    VIRUSTOTAL_API_KEY = '522906139fea521069dc9f03021325c6fc14253b69361401c3c13db66883c2a8'
    VT_TIMEOUT = 60  # Increased timeout
    VT_MAX_RETRIES = 3
    VT_RETRY_DELAY = 15  # seconds
    VT_RATE_LIMIT_DELAY = 20  # seconds between scans
    
    # YARA Configuration
    YARA_RULES_DIR = os.path.join(Path(__file__).parent.parent, 'data', 'yara')
    YARA_RULES_PATH = os.path.abspath(os.path.join(
        os.path.dirname(__file__),
        '..', 'data', 'yara', 'yara-rules-full.yar'
    ))
    
    #YARA_MAX_MATCHES = 1000
    
    @staticmethod
    def init_app(app):
        """Ensure required directories exist"""
        os.makedirs(os.path.dirname(app.config['YARA_RULES_PATH']), exist_ok=True)
        if not os.path.exists(app.config['YARA_RULES_PATH']):
            raise FileNotFoundError(f"YARA rules file missing at {app.config['YARA_RULES_PATH']}")
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        os.makedirs(app.config['YARA_RULES_DIR'], exist_ok=True)