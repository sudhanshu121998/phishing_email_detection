class Settings: 
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Settings, cls).__new__(cls)
            cls._settings = {
                'suspicious_domains': [
                    'phishing.com',
                    'malicious.com',
                    'login-secure.com',
                    'verify-update.com',
                    'paypal-security.com',
                    'secure-microsoft.com',
                    'bank-account-alert.com',
                    'icloud-login.com',
                    'update-now.com',
                    'security-check.com',
                    'account-recovery.com',
                    'alert-user.com',
                    'urgent-verification.com',
                    'secure-access.com',
                    'mail-verification.com',
                    'account-update.com',
                    'auth-check.com',
                    'reset-password-now.com',
                    'secure-mail.com',
                    'support-team-alert.com'
            ],
    'urgent_keywords': ['urgent', 'immediate', 'action required']
}

        return cls._instance

    def get_setting(self, key):
        return self.__class__._settings.get(key)
