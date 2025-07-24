import subprocess
import logging

logger = logging.getLogger(__name__)

def strings_analysis(filepath, min_length=8):
    try:
        result = subprocess.run(
            ['strings', f'-n{min_length}', filepath],
            capture_output=True,
            text=True,
            timeout=60
        )
        strings = result.stdout.splitlines()
        return {
            'strings': strings,
            'count': len(strings),
            'interesting': [s for s in strings if any(
                kw in s.lower() for kw in 
                ['http', 'https', 'cmd.exe', 'powershell', 'regsvr32']
            )]
        }
    except subprocess.TimeoutExpired:
        return {'error': 'strings timed out'}
    except Exception as e:
        return {'error': str(e)}