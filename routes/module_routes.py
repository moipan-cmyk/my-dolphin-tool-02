# routes/module_routes.py
"""
Module distribution endpoint - serves encrypted core modules to clients
"""

import os
import base64
from flask import Blueprint, request, jsonify, current_app, session
from flask_login import login_required, current_user
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

module_bp = Blueprint('module', __name__, url_prefix='/api/module')

def encrypt_module(code, key):
    """
    Encrypt module code with AES using session key.
    key is the per-session key (32 bytes for AES-256)
    """
    try:
        # Ensure key is 32 bytes
        key_bytes = key.encode()[:32].ljust(32, b'\0')
        iv = key_bytes[:16]  # Use first 16 bytes as IV
        
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        padded_data = pad(code.encode(), AES.block_size)
        encrypted = cipher.encrypt(padded_data)
        
        return base64.b64encode(encrypted).decode()
    except Exception as e:
        print(f"Encryption error: {e}")
        return None

@module_bp.route('/get', methods=['POST'])
@login_required
def get_module():
    """
    Return encrypted source code of a requested module.
    Expects JSON: {"module": "adb"}
    """
    try:
        data = request.get_json()
        module_name = data.get('module')
        
        if not module_name:
            return jsonify({'error': 'Module name required'}), 400
        
        # 1. License validation
        user = current_user
        if not user.is_license_valid():
            return jsonify({'error': 'License invalid or expired'}), 403
        
        # 2. Get session key from Flask session
        session_key = session.get('module_key')
        if not session_key:
            return jsonify({'error': 'No session key found. Please login again.'}), 401
        
        # 3. Locate the module file
        core_modules_dir = current_app.config.get('CORE_MODULES_DIR', 'core_modules')
        module_path = os.path.join(core_modules_dir, f'{module_name}.py')
        
        if not os.path.exists(module_path):
            # Try alternative path (in case modules are in Core folder)
            alt_path = os.path.join(current_app.root_path, 'Core', f'{module_name}.py')
            if os.path.exists(alt_path):
                module_path = alt_path
            else:
                return jsonify({'error': f'Module "{module_name}" not found'}), 404
        
        # 4. Read the module code
        with open(module_path, 'r', encoding='utf-8') as f:
            code = f.read()
        
        # 5. Encrypt the code
        encrypted_code = encrypt_module(code, session_key)
        
        if not encrypted_code:
            return jsonify({'error': 'Failed to encrypt module'}), 500
        
        return jsonify({
            'success': True,
            'code': encrypted_code,
            'module': module_name,
            'encrypted': True
        }), 200
        
    except Exception as e:
        print(f"Error serving module: {e}")
        return jsonify({'error': str(e)}), 500

@module_bp.route('/list', methods=['GET'])
@login_required
def list_modules():
    """
    List all available modules (for debugging)
    """
    try:
        core_modules_dir = current_app.config.get('CORE_MODULES_DIR', 'core_modules')
        modules = []
        
        if os.path.exists(core_modules_dir):
            for file in os.listdir(core_modules_dir):
                if file.endswith('.py') and not file.startswith('__'):
                    modules.append(file.replace('.py', ''))
        
        # Also check Core directory
        core_dir = os.path.join(current_app.root_path, 'Core')
        if os.path.exists(core_dir):
            for file in os.listdir(core_dir):
                if file.endswith('.py') and not file.startswith('__'):
                    module_name = file.replace('.py', '')
                    if module_name not in modules:
                        modules.append(module_name)
        
        return jsonify({
            'success': True,
            'modules': sorted(modules)
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500