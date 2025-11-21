# mobile_server.py - Simple HTTP server to serve password files
import http.server
import socketserver
import json
import os
from urllib.parse import parse_qs, urlparse
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class PasswordServerHandler(http.server.SimpleHTTPRequestHandler):
    
    def generate_key_from_password(self, password, salt):
        """Generate encryption key from master password"""
        password_bytes = password.encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        return key
    
    def load_passwords(self, master_password):
        """Load and decrypt passwords"""
        try:
            with open('salt.key', 'rb') as f:
                salt = f.read()
            
            key = self.generate_key_from_password(master_password, salt)
            cipher_suite = Fernet(key)
            
            with open('passwords.enc', 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = cipher_suite.decrypt(encrypted_data)
            data = json.loads(decrypted_data.decode())
            
            if 'passwords' in data:
                return data['passwords']
            else:
                return data
        except Exception as e:
            print(f"Error loading passwords: {e}")
            return None
    
    def do_GET(self):
        if self.path == '/':
            self.send_mobile_app()
        elif self.path.startswith('/api/passwords'):
            self.handle_password_request()
        else:
            super().do_GET()
    
    def send_mobile_app(self):
        """Send mobile-optimized HTML app"""
        html = '''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Manager Mobile</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #f0f0f0; 
            padding: 10px;
            min-height: 100vh;
        }
        .container { max-width: 100%; }
        .login-form, .main-app { 
            background: white; 
            border-radius: 12px; 
            padding: 20px; 
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        input[type="password"], input[type="text"] { 
            width: 100%; 
            padding: 15px; 
            border: 1px solid #ddd; 
            border-radius: 8px; 
            font-size: 16px;
            margin-bottom: 15px;
        }
        button { 
            width: 100%; 
            padding: 15px; 
            background: #007AFF; 
            color: white; 
            border: none; 
            border-radius: 8px; 
            font-size: 16px;
            cursor: pointer;
            margin-bottom: 10px;
            transition: background 0.2s;
        }
        button:hover { background: #0056b3; }
        button:active { background: #004494; }
        .password-item { 
            background: #f8f9fa; 
            border-radius: 8px; 
            padding: 15px; 
            margin-bottom: 10px;
            border-left: 4px solid #007AFF;
        }
        .password-item h3 { 
            font-size: 18px; 
            margin-bottom: 5px; 
            color: #333;
        }
        .password-item p { 
            color: #666; 
            font-size: 14px; 
            margin-bottom: 10px; 
            word-break: break-word;
        }
        .button-group { 
            display: flex; 
            gap: 10px; 
        }
        .button-group button { 
            width: auto; 
            flex: 1; 
            padding: 10px; 
            margin-bottom: 0; 
            font-size: 14px;
        }
        .search-box { margin-bottom: 20px; }
        .hidden { display: none; }
        .error { 
            color: #ff3b30; 
            text-align: center; 
            margin: 10px 0; 
            padding: 10px;
            background: #ffebee;
            border-radius: 8px;
        }
        .success { 
            color: #28cd41; 
            text-align: center; 
            margin: 10px 0; 
            padding: 10px;
            background: #e8f5e8;
            border-radius: 8px;
        }
        h1 { 
            text-align: center; 
            margin-bottom: 20px; 
            color: #333; 
        }
        .logout-btn { 
            background: #ff3b30; 
            margin-top: 10px;
        }
        .logout-btn:hover { background: #d12b20; }
        .stats { 
            text-align: center; 
            color: #666; 
            font-size: 14px; 
            margin-bottom: 15px;
        }
        .loading { 
            text-align: center; 
            padding: 20px; 
            color: #666;
        }
        .notes { 
            font-size: 12px; 
            color: #999; 
            margin-top: 5px; 
            font-style: italic;
        }
        @media (max-width: 480px) {
            body { padding: 5px; }
            .login-form, .main-app { padding: 15px; }
            .password-item { padding: 12px; }
            button { padding: 12px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Login Screen -->
        <div id="loginScreen" class="login-form">
            <h1>🔐 Password Manager</h1>
            <input type="password" id="masterPasswordInput" placeholder="Enter Master Password" autocomplete="current-password">
            <button onclick="login()">Login</button>
            <div id="loginError" class="error" style="display: none;"></div>
            <div style="text-align: center; margin-top: 20px; font-size: 12px; color: #666;">
                Read-only access to your desktop password manager
            </div>
        </div>

        <!-- Main App -->
        <div id="mainApp" class="hidden">
            <div class="main-app">
                <h1>🔐 Your Passwords</h1>
                <div id="stats" class="stats"></div>
                
                <div class="search-box">
                    <input type="text" id="searchInput" placeholder="Search passwords..." onkeyup="filterPasswords()">
                </div>
                
                <div id="passwordList">
                    <!-- Passwords will be loaded here -->
                </div>
                
                <div id="message"></div>
                
                <button onclick="logout()" class="logout-btn">Logout</button>
            </div>
        </div>
    </div>

    <script>
        let masterPassword = '';
        let allPasswords = {};
        let filteredCount = 0;

        async function login() {
            const passwordInput = document.getElementById('masterPasswordInput');
            const password = passwordInput.value;
            const errorDiv = document.getElementById('loginError');
            
            if (!password) {
                showLoginError('Please enter master password');
                return;
            }

            // Show loading state
            const loginBtn = document.querySelector('button');
            const originalText = loginBtn.textContent;
            loginBtn.textContent = 'Logging in...';
            loginBtn.disabled = true;

            try {
                const response = await fetch(`/api/passwords?password=${encodeURIComponent(password)}`);
                const result = await response.json();
                
                if (result.success) {
                    masterPassword = password;
                    allPasswords = result.passwords;
                    showMainApp();
                    displayPasswords();
                    updateStats();
                } else {
                    showLoginError(result.message || 'Invalid master password');
                    passwordInput.value = '';
                    passwordInput.focus();
                }
            } catch (error) {
                console.error('Login error:', error);
                showLoginError('Connection error. Make sure the server is running.');
            } finally {
                loginBtn.textContent = originalText;
                loginBtn.disabled = false;
            }
        }

        function showLoginError(message) {
            const errorDiv = document.getElementById('loginError');
            errorDiv.textContent = message;
            errorDiv.style.display = 'block';
            setTimeout(() => {
                errorDiv.style.display = 'none';
            }, 5000);
        }

        function showMainApp() {
            console.log('showMainApp called');
            const loginScreen = document.getElementById('loginScreen');
            const mainApp = document.getElementById('mainApp');
            
            console.log('Login screen element:', loginScreen);
            console.log('Main app element:', mainApp);
            
            if (loginScreen && mainApp) {
                loginScreen.classList.add('hidden');
                mainApp.classList.remove('hidden');
                console.log('Screen switched successfully');
            } else {
                console.error('Could not find required DOM elements');
            }
        }

        function logout() {
            masterPassword = '';
            allPasswords = {};
            document.getElementById('loginScreen').classList.remove('hidden');
            document.getElementById('mainApp').classList.add('hidden');
            document.getElementById('masterPasswordInput').value = '';
            document.getElementById('loginError').style.display = 'none';
            document.getElementById('masterPasswordInput').focus();
        }

        function updateStats() {
            const totalCount = Object.keys(allPasswords).length;
            const statsDiv = document.getElementById('stats');
            if (filteredCount !== totalCount) {
                statsDiv.textContent = `Showing ${filteredCount} of ${totalCount} passwords`;
            } else {
                statsDiv.textContent = `${totalCount} password${totalCount !== 1 ? 's' : ''} total`;
            }
        }

        function displayPasswords() {
            const searchTerm = document.getElementById('searchInput').value.toLowerCase();
            const passwordList = document.getElementById('passwordList');
            passwordList.innerHTML = '';
            filteredCount = 0;

            if (Object.keys(allPasswords).length === 0) {
                passwordList.innerHTML = '<div class="loading">No passwords found. Add some using the desktop app!</div>';
                updateStats();
                return;
            }

            Object.keys(allPasswords).sort().forEach(service => {
                const data = allPasswords[service];
                
                if (!searchTerm || 
                    service.toLowerCase().includes(searchTerm) || 
                    data.username.toLowerCase().includes(searchTerm) ||
                    (data.notes && data.notes.toLowerCase().includes(searchTerm))) {
                    
                    filteredCount++;
                    
                    const item = document.createElement('div');
                    item.className = 'password-item';
                    
                    let notesHtml = '';
                    if (data.notes && data.notes.trim()) {
                        notesHtml = `<div class="notes">${escapeHtml(data.notes)}</div>`;
                    }
                    
                    item.innerHTML = `
                        <h3>${escapeHtml(service)}</h3>
                        <p>${escapeHtml(data.username)}</p>
                        ${notesHtml}
                        <div class="button-group">
                            <button onclick="copyText('${escapeForJs(data.username)}', 'Username')">📋 Copy User</button>
                            <button onclick="copyText('${escapeForJs(data.password)}', 'Password')">🔑 Copy Pass</button>
                        </div>
                    `;
                    passwordList.appendChild(item);
                }
            });

            if (filteredCount === 0 && searchTerm) {
                passwordList.innerHTML = '<div class="loading">No passwords match your search.</div>';
            }

            updateStats();
        }

        function filterPasswords() {
            displayPasswords();
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        function escapeForJs(text) {
            return text.replace(/'/g, "\\'").replace(/\"/g, '\\"').replace(/\n/g, '\\n');
        }

        async function copyText(text, type) {
            try {
                if (navigator.clipboard && window.isSecureContext) {
                    await navigator.clipboard.writeText(text);
                } else {
                    // Fallback for older browsers or non-HTTPS
                    const textArea = document.createElement('textarea');
                    textArea.value = text;
                    textArea.style.position = 'fixed';
                    textArea.style.opacity = '0';
                    textArea.style.top = '-9999px';
                    document.body.appendChild(textArea);
                    textArea.select();
                    textArea.setSelectionRange(0, 99999); // For mobile
                    document.execCommand('copy');
                    document.body.removeChild(textArea);
                }
                showMessage(`${type} copied to clipboard! 📋`, 'success');
            } catch (error) {
                console.error('Copy failed:', error);
                showMessage('Failed to copy to clipboard ❌', 'error');
            }
        }

        function showMessage(message, type = 'success') {
            const messageDiv = document.getElementById('message');
            messageDiv.textContent = message;
            messageDiv.className = type;
            setTimeout(() => {
                messageDiv.textContent = '';
                messageDiv.className = '';
            }, 3000);
        }

        // Auto-focus on password input
        document.addEventListener('DOMContentLoaded', function() {
            document.getElementById('masterPasswordInput').focus();
        });

        // Allow Enter key to login
        document.getElementById('masterPasswordInput').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                login();
            }
        });

        // Prevent form submission on Enter in search
        document.getElementById('searchInput').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                e.preventDefault();
            }
        });
    </script>
</body>
</html>'''
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        self.end_headers()
        self.wfile.write(html.encode())
    
    def handle_password_request(self):
        """Handle API request for passwords"""
        try:
            # Parse query parameters
            query = urlparse(self.path).query
            params = parse_qs(query)
            master_password = params.get('password', [None])[0]
            
            if not master_password:
                self.send_json_response({'success': False, 'message': 'Master password required'})
                return
            
            passwords = self.load_passwords(master_password)
            if passwords is None:
                self.send_json_response({'success': False, 'message': 'Invalid master password or unable to decrypt database'})
                return
            
            self.send_json_response({'success': True, 'passwords': passwords})
            
        except Exception as e:
            print(f"API Error: {e}")
            self.send_json_response({'success': False, 'message': f'Server error: {str(e)}'})
    
    def send_json_response(self, data):
        """Send JSON response"""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')  # Allow cross-origin requests
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def log_message(self, format, *args):
        """Override to reduce log spam, but still show important info"""
        if "GET /" in format % args and "200" in format % args:
            print(f"📱 Mobile client connected from {self.address_string()}")
        elif "GET /api/passwords" in format % args:
            if "200" in format % args:
                print(f"🔓 Password access from {self.address_string()}")
            else:
                print(f"❌ Failed login attempt from {self.address_string()}")

def start_mobile_server(port=8080):
    """Start the mobile companion server"""
    
    print("🔐 Password Manager Mobile Server")
    print("=" * 40)
    
    # Check if password files exist
    if not os.path.exists('passwords.enc'):
        print("❌ passwords.enc not found!")
        print("Make sure you run this in the same folder as your desktop password manager.")
        print("Create some passwords using the desktop app first.")
        return
    
    if not os.path.exists('salt.key'):
        print("❌ salt.key not found!")
        print("Make sure you run this in the same folder as your desktop password manager.")
        return
    
    try:
        with socketserver.TCPServer(("", port), PasswordServerHandler) as httpd:
            print(f"✅ Password database files found")
            print(f"🚀 Server starting on port {port}")
            print()
            print(f"📍 Access URLs:")
            print(f"   Local: http://localhost:{port}")
            
            # Try to get local IP address
            import socket
            try:
                # Connect to Google DNS to get local IP
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                s.close()
                print(f"   Network: http://{local_ip}:{port}")
                print(f"   Tailscale: http://100.x.x.x:{port} (replace with your Tailscale IP)")
            except:
                print("   Network: Could not determine local IP")
            
            print()
            print(f"📱 Mobile Access Instructions:")
            print(f"   1. Connect your phone to Tailscale")
            print(f"   2. Find your computer's Tailscale IP (100.x.x.x)")
            print(f"   3. Open browser on phone: http://100.x.x.x:{port}")
            print(f"   4. Enter your master password")
            
            print()
            print(f"🔒 Security Features:")
            print(f"   • Same encryption as desktop app")
            print(f"   • Read-only access (can't modify passwords)")
            print(f"   • Works with existing password database")
            print(f"   • No data sent to external servers")
            
            print()
            print(f"⚠️  Important Notes:")
            print(f"   • Keep your desktop app's password files safe")
            print(f"   • This server provides read-only access")
            print(f"   • Use desktop app to add/edit/delete passwords")
            print(f"   • Server auto-stops when you close this window")
            
            print()
            print(f"🔴 Press Ctrl+C to stop the server")
            print("=" * 40)
            
            httpd.serve_forever()
            
    except OSError as e:
        if "Address already in use" in str(e):
            print(f"❌ Port {port} is already in use.")
            print(f"Try a different port: python mobile_server.py {port + 1}")
        else:
            print(f"❌ Error starting server: {e}")
    except KeyboardInterrupt:
        print(f"\n👋 Server stopped gracefully")
        print("Your password files remain encrypted and secure.")

if __name__ == "__main__":
    import sys
    
    port = 8080
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print("Usage: python mobile_server.py [port]")
            print("Example: python mobile_server.py 8080")
            sys.exit(1)
    
    start_mobile_server(port)