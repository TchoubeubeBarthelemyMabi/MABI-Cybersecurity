from flask import request, abort

def attach_security(app):
    @app.before_request
    def detect_intrusion():
        # Motifs suspects dans les requêtes
        suspicious_patterns = [
            '<script>', 'drop table', 'union select', '1=1', '<?php',
            'onerror=', '<iframe', 'alert(', 'document.cookie'
        ]

        # 🔎 Vérifie l'URL de la requête
        url_check = request.url.lower()
        for p in suspicious_patterns:
            if p in url_check:
                app.logger.warning(f"[SEC ALERT] Motif suspect '{p}' trouvé dans l'URL: {request.url}")
                abort(400, description="🔒 Requête bloquée : contenu malveillant détecté.")

        # 🔐 Vérifie les données POST (formulaires)
        if request.method == "POST":
            for value in request.form.values():
                value_lower = value.lower()
                for p in suspicious_patterns:
                    if p in value_lower:
                        app.logger.warning(f"[SEC ALERT] Motif suspect '{p}' trouvé dans les données POST.")
                        abort(400, description="🔒 Requête bloquée : contenu malveillant dans formulaire.")
