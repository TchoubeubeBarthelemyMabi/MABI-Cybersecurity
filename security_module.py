from flask import request, abort

def attach_security(app):
    @app.before_request
    def detect_intrusion():
        suspicious_patterns = [
            '<script>', 'drop table', 'union select', '1=1', '<?php'
        ]
        # URL malveillante ?
        for p in suspicious_patterns:
            if p in request.url.lower():
                app.logger.warning(f"[SEC ALERT] {p} found in URL: {request.url}")
                abort(400, description="Bad request detected.")
        # POST malveillant ?
        if request.method == "POST":
            for value in request.form.values():
                if p in value.lower():
                    app.logger.warning(f"[SEC ALERT] {p} found in POST data.")
                    abort(400, description="Bad request detected.")