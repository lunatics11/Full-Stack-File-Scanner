from dotenv import load_dotenv
import os
from pathlib import Path


class Config:
    load_dotenv()
    # Flask and Application Configuration
    SECRET_KEY = os.getenv('SECRET_KEY')
    UPLOAD_FOLDER = os.path.join(Path(__file__).parent.parent, 'static', 'uploads')
    MAX_CONTENT_LENGTH = 32 * 1024 * 1024  # 32MB limit for file uploads

    # VirusTotal Configuration

    VT_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
    VT_TIMEOUT = 60  # Request timeout in seconds
    VT_MAX_RETRIES = 3  # Max API retries
    VT_RETRY_DELAY = 15  # Seconds between retries
    VT_RATE_LIMIT_DELAY = 20  # Seconds between scans to avoid rate limiting

    # YARA Rules Configuration
    YARA_RULES_DIR = os.path.join(Path(__file__).parent.parent, 'data', 'yara')
    YARA_RULES_PATH = os.path.abspath(os.path.join(
        os.path.dirname(__file__),
        '..', 'data', 'yara', 'yara-rules-full.yar'
    ))

    @staticmethod
    def init_app(app):
        """Initialize application configuration and validate required settings"""
        # Validate VirusTotal API Key
        if not Config.VT_API_KEY:
            raise ValueError(
                "VirusTotal API key not configured.\n"
                "Set VIRUSTOTAL_API_KEY in either:\n"
                "1. Render environment variables (production)\n"
                "2. .env file (development)"
            )

        # Ensure directories exist
        required_dirs = [
            app.config['UPLOAD_FOLDER'],
            app.config['YARA_RULES_DIR']
        ]

        for directory in required_dirs:
            os.makedirs(directory, exist_ok=True)

        # Validate YARA rules file exists
        if not os.path.exists(app.config['YARA_RULES_PATH']):
            raise FileNotFoundError(
                f"YARA rules file missing at {app.config['YARA_RULES_PATH']}\n"
                "Please ensure the rules file is in the correct location."
            )


# Instantiate the configuration
config = Config()