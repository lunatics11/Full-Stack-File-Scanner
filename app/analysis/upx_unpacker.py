import subprocess
import tempfile
import os
import logging

logger = logging.getLogger(__name__)

def unpack_if_upx(filepath):
    result = {'packed': False, 'unpacked': False}
    
    try:
        # Check if UPX packed
        check = subprocess.run(
            ['upx', '-q', '-t', filepath],
            capture_output=True,
            text=True
        )
        
        if "not packed by UPX" not in check.stderr:
            result['packed'] = True
            
            # Create temp file for unpacked version
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                unpacked_path = tmp.name
            
            # Perform unpacking
            subprocess.run(
                ['upx', '-q', '-d', filepath, '-o', unpacked_path],
                check=True,
                capture_output=True
            )
            
            result.update({
                'unpacked': True,
                'unpacked_path': unpacked_path,
                'original_size': os.path.getsize(filepath),
                'unpacked_size': os.path.getsize(unpacked_path)
            })
        
    except subprocess.CalledProcessError as e:
        result['error'] = f"UPX failed: {e.stderr}"
    except Exception as e:
        result['error'] = str(e)
    
    return result