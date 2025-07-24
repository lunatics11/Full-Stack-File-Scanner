import subprocess
import json
import logging

logger = logging.getLogger(__name__)

def exiftool_analysis(filepath):
    try:
        result = subprocess.run(
            ['exiftool', '-j', filepath],
            capture_output=True,
            text=True,
            timeout=30
        )
        return json.loads(result.stdout)[0] if result.stdout else {}
    except subprocess.TimeoutExpired:
        return {'error': 'exiftool timed out'}
    except Exception as e:
        return {'error': str(e)}