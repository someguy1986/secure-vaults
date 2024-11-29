import json
import sqlite3
from cryptography.fernet import Fernet

class RBAC:
    """Role-Based Access Control class."""
    roles_permissions = {
        'admin': {'read', 'write', 'delete'},
        'user': {'read'}
    }

    def check_access(self, role: str, action: str) -> bool:
        return action in self.roles_permissions.get(role, set())

def setup_database():
    """Sets up the database for users and logs."""
    conn = sqlite3.connect('enterprise_vault.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, 
            username TEXT NOT NULL UNIQUE, 
            role TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY, 
            timestamp TEXT NOT NULL, 
            user TEXT NOT NULL, 
            action TEXT NOT NULL, 
            status TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

class SecureVault:
    def __init__(self, key):
        self.key = key
        self.rbac = RBAC()
        self.conn = sqlite3.connect('enterprise_vault.db')
        self.cursor = self.conn.cursor()
        self.data = {}  # For now, keeping data in memory

    def log_action(self, username, action, status):
        """Logs actions into the audit_logs table."""
        self.cursor.execute('''
            INSERT INTO audit_logs (timestamp, user, action, status) 
            VALUES (datetime('now'), ?, ?, ?)
        ''', (username, action, status))
        self.conn.commit()

    def add_data(self, username: str, data: str, action: str): 
        self.cursor.execute('SELECT role FROM users WHERE username=%s', (username,)) # Parameterized query
        result = self.cursor.fetchone()
        if not result:
            self.log_action(username, action, "Failed: User not found")
            raise ValueError("User not found")
        role = result[0]

        if not self.rbac.check_access(role, action):
            self.log_action(username, action, "Failed: Unauthorized")
            raise PermissionError("Unauthorized access!")

        encrypted_data = Fernet(self.key).encrypt(data.encode())
        self.data["vault"] = encrypted_data  # Store in memory (for now)
        self.log_action(username, action, "Success")

    def retrieve_data(self, username, action):
        self.cursor.execute('SELECT role FROM users WHERE username=%s', (username,)) # Parameterized query
        result = self.cursor.fetchone()
        if not result:
            self.log_action(username, action, "Failed: User not found")
            raise ValueError("User not found")
        role = result[0]

        if not self.rbac.check_access(role, action):
            self.log_action(username, action, f"Failed: Unauthorized") 
            raise PermissionError("Unauthorized access!")

        encrypted_data = self.data.get("vault")
        if encrypted_data:
            self.log_action(username, action, "Success")
            return Fernet(self.key).decrypt(encrypted_data).decode()
        self.log_action(username, action, "Failed: No data found")
        return None

setup_database()

conn = sqlite3.connect('enterprise_vault.db')
cursor = conn.cursor()
# Using parameterized queries
cursor.execute("INSERT OR IGNORE INTO users (username, role) VALUES (%s, %s)", ("admin_user", "admin"))  
cursor.execute("INSERT OR IGNORE INTO users (username, role) VALUES (%s, %s)", ("regular_user", "user"))
conn.commit()
conn.close()

key = Fernet.generate_key()  # How is this key managed long-term?
vault = SecureVault(key=key)

vault.add_data("admin_user", "Sensitive enterprise data", 'write')
try:
    print(vault.retrieve_data("admin_user", 'read'))
    print(vault.retrieve_data("regular_user", 'read'))
except Exception as e:
    print(e)

conn = sqlite3.connect('enterprise_vault.db')
cursor = conn.cursor()
cursor.execute("SELECT * FROM audit_logs")
print(cursor.fetchall())
conn.close()