"""
Security & Token verification services for GRC platform magic link intake and user auth.
"""
import hmac
import hashlib
import base64
import json
import secrets
from datetime import datetime, timedelta, timezone

class GRCAuthService:
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using PBKDF2-HMAC-SHA256."""
        salt = secrets.token_hex(16)
        key = hashlib.pbkdf2_hmac(
            "sha256", 
            password.encode("utf-8"), 
            salt.encode("utf-8"), 
            100_000
        )
        return f"{salt}:{key.hex()}"

    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """Verify password against storage hash."""
        try:
            salt, stored_key_hex = hashed.split(":")
            key = hashlib.pbkdf2_hmac(
                "sha256", 
                password.encode("utf-8"), 
                salt.encode("utf-8"), 
                100_000
            )
            return secrets.compare_digest(key.hex(), stored_key_hex)
        except ValueError:
            return False

    @staticmethod
    def generate_magic_token(email: str, vendor_id: str, secret_key: str, expires_in_hours: int = 48) -> str:
        """Generate a secure, signed base64 magic token for passwordless logins."""
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=expires_in_hours)).isoformat()
        payload = {
            "email": email,
            "vendor_id": vendor_id,
            "expires_at": expires_at,
            "nonce": secrets.token_hex(8)
        }
        
        # Base64 encode the payload JSON string
        payload_bytes = json.dumps(payload).encode("utf-8")
        payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode("utf-8")
        
        # Calculate HMAC-SHA256 signature
        sig = hmac.new(
            secret_key.encode("utf-8"), 
            payload_b64.encode("utf-8"), 
            hashlib.sha256
        ).hexdigest()
        
        return f"{payload_b64}.{sig}"

    @staticmethod
    def verify_magic_token(token: str, secret_key: str) -> dict | None:
        """Verify the signature and expiration of a magic token."""
        try:
            if "." not in token:
                return None
            payload_b64, sig = token.split(".")
            
            # Recalculate signature to verify integrity
            expected_sig = hmac.new(
                secret_key.encode("utf-8"), 
                payload_b64.encode("utf-8"), 
                hashlib.sha256
            ).hexdigest()
            
            if not secrets.compare_digest(sig, expected_sig):
                return None
            
            # Decode payload
            payload_bytes = base64.urlsafe_b64decode(payload_b64.encode("utf-8"))
            payload = json.loads(payload_bytes.decode("utf-8"))
            
            # Check expiration
            expires_at = datetime.fromisoformat(payload["expires_at"])
            if datetime.now(timezone.utc) > expires_at:
                return None
                
            return payload
        except Exception:
            return None
