from dotenv import load_dotenv
import os
from pathlib import Path

# Load .env (works locally, ignored on Render if not present)
load_dotenv()


class Config:
    # Flask Configuration
    SECRET_KEY = os.getenv(
        "SECRET_KEY",
        "change-this-secret-key-in-production"
    )

    UPLOAD_FOLDER = os.path.join(
        Path(__file__).parent.parent,
        "static",
        "uploads"
    )

    MAX_CONTENT_LENGTH = 32 * 1024 * 1024  # 32 MB

    # VirusTotal
    VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
    VT_TIMEOUT = 60
    VT_MAX_RETRIES = 3
    VT_RETRY_DELAY = 15
    VT_RATE_LIMIT_DELAY = 20

    # YARA
    YARA_RULES_DIR = os.path.join(
        Path(__file__).parent.parent,
        "data",
        "yara"
    )

    YARA_RULES_PATH = os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            "..",
            "data",
            "yara",
            "yara-rules-full.yar"
        )
    )

    @staticmethod
    def init_app(app):

        # Create required directories
        os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
        os.makedirs(app.config["YARA_RULES_DIR"], exist_ok=True)

        # Warn if VirusTotal key is missing
        if not Config.VT_API_KEY:
            app.logger.warning(
                "VirusTotal API key not configured. "
                "VirusTotal scanning will be disabled."
            )

        # Warn if YARA rules are missing
        if not os.path.exists(app.config["YARA_RULES_PATH"]):
            app.logger.warning(
                f"YARA rules not found at {app.config['YARA_RULES_PATH']}. "
                "YARA scanning will be disabled."
            )


config = Config()