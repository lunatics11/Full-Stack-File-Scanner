from flask import current_app
import yara
import os

yara_rules = None

def init_yara(app):
    global yara_rules
    try:
        if os.path.exists(app.config['YARA_RULES_PATH']):
            yara_rules = yara.load(app.config['YARA_RULES_PATH'])
        else:
            rule_files = []
            for root, _, files in os.walk(app.config['YARA_RULES_DIR']):
                for file in files:
                    if file.endswith('.yar'):
                        rule_files.append(os.path.join(root, file))
            
            yara_rules = yara.compile(filepaths={
                os.path.basename(f): f for f in rule_files
            })
    except Exception as e:
        app.logger.error(f"Failed to initialize YARA rules: {str(e)}")
        yara_rules = None