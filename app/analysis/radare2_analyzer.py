import subprocess
import json
import logging

logger = logging.getLogger(__name__)

def radare2_analysis(filepath):
    try:
        commands = [
            'aaa',
            'iIj',
            'iEj',
            'iSj',
            'izzj'
        ]
        output = {}
        for cmd in commands:
            result = subprocess.run(
                ['r2', '-q0', '-c', cmd, filepath],
                capture_output=True,
                text=True,
                timeout=120
            )
            try:
                output[cmd] = json.loads(result.stdout.strip())
            except json.JSONDecodeError:
                output[cmd] = result.stdout.strip()
        return output
    except Exception as e:
        return {'error': str(e)}