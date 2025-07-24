import subprocess
import json
import logging

logger = logging.getLogger(__name__)

def peframe_analysis(filepath):
    try:
        result = subprocess.run(
            ['peframe', '--json', filepath],
            capture_output=True,
            text=True,
            timeout=60
        )
        return json.loads(result.stdout) if result.stdout else {}
    except subprocess.TimeoutExpired:
        return {'error': 'peframe timed out'}
    except Exception as e:
        return {'error': str(e)}