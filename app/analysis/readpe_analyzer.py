import subprocess
import logging

logger = logging.getLogger(__name__)

def readpe_analysis(filepath):
    try:
        result = subprocess.run(
            ['readpe', '-f', '-h', '-i', '-d', '-s', filepath],
            capture_output=True,
            text=True,
            timeout=60
        )
        return {'output': result.stdout} if result.stdout else {}
    except subprocess.TimeoutExpired:
        return {'error': 'readpe timed out'}
    except Exception as e:
        return {'error': str(e)}