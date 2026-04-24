import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import os
from dotenv import load_dotenv
from flask import current_app

load_dotenv()

# Configure logging
logger = logging.getLogger(__name__)

# Default values from environment (will be overridden by app config if available)
SENDER_EMAIL = os.environ.get('SENDER_EMAIL', 'your-email@gmail.com')
SENDER_PASSWORD = os.environ.get('SENDER_PASSWORD', 'your-app-password')
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))

def get_email_config():
    """Get email configuration from Flask app context or environment"""
    try:
        # Try to get from Flask app config first
        from flask import current_app
        return {
            'sender': current_app.config.get('MAIL_USERNAME', SENDER_EMAIL),
            'password': current_app.config.get('MAIL_PASSWORD', SENDER_PASSWORD),
            'server': current_app.config.get('MAIL_SERVER', SMTP_SERVER),
            'port': current_app.config.get('MAIL_PORT', SMTP_PORT)
        }
    except:
        # Fall back to environment variables
        return {
            'sender': SENDER_EMAIL,
            'password': SENDER_PASSWORD,
            'server': SMTP_SERVER,
            'port': SMTP_PORT
        }

def send_admission_email(recipient_email, username, admission_number, license_type=None, license_expiry=None):
    """
    Send email with admission number to newly registered user
    
    Args:
        recipient_email (str): User's email address
        username (str): User's username
        admission_number (str/int): Generated admission number
        license_type (str, optional): 'Fair', 'Good', or 'Excellent'
        license_expiry (datetime, optional): License expiry date
    """
    try:
        config = get_email_config()
        
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "🎫 Welcome to DOLPHIN BYPASS TOOL - Your Admission Number"
        msg["From"] = config['sender']
        msg["To"] = recipient_email
        
        # Create HTML email body
        html = f"""
        <html>
            <head>
                <style>
                    body {{ font-family: 'Segoe UI', Arial, sans-serif; background-color: #f4f4f4; padding: 20px; }}
                    .container {{ max-width: 600px; margin: 0 auto; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 3px; border-radius: 12px; }}
                    .content {{ background-color: white; padding: 30px; border-radius: 10px; }}
                    h1 {{ color: #333; text-align: center; margin-bottom: 30px; }}
                    .logo {{ text-align: center; font-size: 24px; font-weight: bold; color: #0400FF; margin-bottom: 20px; }}
                    .welcome {{ font-size: 18px; color: #333; margin-bottom: 20px; }}
                    .credentials {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; border-radius: 8px; margin: 20px 0; color: white; }}
                    .admission-number {{ font-size: 32px; font-weight: bold; text-align: center; padding: 10px; background: rgba(255,255,255,0.2); border-radius: 5px; margin: 10px 0; letter-spacing: 2px; }}
                    .license-badge {{ display: inline-block; padding: 5px 10px; border-radius: 5px; font-weight: bold; }}
                    .license-fair {{ background: #ffd700; color: #000; }}
                    .license-good {{ background: #4CAF50; color: white; }}
                    .license-excellent {{ background: #9c27b0; color: white; }}
                    .info-box {{ background-color: #f9f9f9; padding: 15px; border-left: 4px solid #0400FF; margin: 15px 0; }}
                    .footer {{ margin-top: 30px; text-align: center; color: #999; font-size: 12px; }}
                    .warning {{ background-color: #fff3cd; padding: 10px; border-radius: 5px; color: #856404; margin: 15px 0; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="content">
                        <div class="logo">🐬 DOLPHIN BYPASS TOOL</div>
                        
                        <div class="welcome">Hello <strong>{username}</strong>!</div>
                        
                        <p>Thank you for registering with DOLPHIN BYPASS TOOL. Your account has been successfully created.</p>
                        
                        <div class="credentials">
                            <h3 style="margin-top: 0; color: white;">🔐 Your Login Credentials:</h3>
                            
                            <div style="margin-bottom: 15px;">
                                <div style="opacity: 0.9; margin-bottom: 5px;">Admission Number:</div>
                                <div class="admission-number">{admission_number}</div>
                            </div>
                            
                            <table style="width: 100%; color: white;">
                                <tr>
                                    <td style="padding: 5px 0; opacity: 0.9;">Username:</td>
                                    <td style="padding: 5px 0; font-weight: bold;">{username}</td>
                                </tr>
                                <tr>
                                    <td style="padding: 5px 0; opacity: 0.9;">Email:</td>
                                    <td style="padding: 5px 0; font-weight: bold;">{recipient_email}</td>
                                </tr>
                            </table>
                        </div>
        """
        
        # Add license info if provided
        if license_type and license_expiry:
            expiry_date = license_expiry.strftime('%Y-%m-%d') if isinstance(license_expiry, datetime) else license_expiry
            license_class = f"license-{license_type.lower()}"
            
            # Calculate duration based on license type
            if license_type == 'Fair':
                duration = "3 Months"
            elif license_type == 'Good':
                duration = "6 Months"
            else:  # Excellent
                duration = "12 Months"
            
            html += f"""
                        <div class="info-box">
                            <h3 style="margin-top: 0; color: #333;">✅ License Information:</h3>
                            <p><strong>License Type:</strong> <span class="license-badge {license_class}">{license_type}</span> ({duration})</p>
                            <p><strong>License Expiry:</strong> {expiry_date}</p>
                        </div>
                        
                        <div class="warning">
                            ⚠️ <strong>Important:</strong> Keep your admission number safe! You'll need it every time you login.
                        </div>
            """
        else:
            html += f"""
                        <div class="info-box">
                            <h3 style="margin-top: 0; color: #333;">ℹ️ No License Purchased</h3>
                            <p>You registered without a license. To access the tool, you'll need to purchase one of our license plans:</p>
                            <ul>
                                <li><strong>Fair</strong> - 3 Months</li>
                                <li><strong>Good</strong> - 6 Months</li>
                                <li><strong>Excellent</strong> - 12 Months</li>
                            </ul>
                            <p>Login to your dashboard to purchase a license.</p>
                        </div>
                        
                        <div class="warning">
                            ⚠️ <strong>Note:</strong> You cannot use the tool without an active license.
                        </div>
            """
        
        html += """
                        <p style="margin-top: 30px; color: #666;">
                            <strong>How to Login:</strong><br>
                            1. Open the DOLPHIN BYPASS TOOL application<br>
                            2. Enter your email, admission number, and password<br>
                            3. Your license will be automatically validated
                        </p>
                        
                        <p style="margin-top: 20px; color: #999; font-size: 12px;">
                            If you did not register for this account, please ignore this email.<br>
                            <em>This is an automated message, please do not reply.</em>
                        </p>
                        
                        <hr style="margin-top: 30px; border: none; border-top: 1px solid #ddd;">
                        <div class="footer">
                            <p>DOLPHIN BYPASS TOOL © 2026 - Made in Kenya by Kenyans</p>
                        </div>
                    </div>
                </div>
            </body>
        </html>
        """
        
        # Attach HTML
        part = MIMEText(html, "html")
        msg.attach(part)
        
        # Send email
        with smtplib.SMTP(config['server'], config['port']) as server:
            server.starttls()
            server.login(config['sender'], config['password'])
            server.sendmail(config['sender'], recipient_email, msg.as_string())
        
        logger.info(f"✅ Admission email sent to {recipient_email}")
        return True, "Email sent successfully"
    
    except Exception as e:
        logger.error(f"❌ Error sending admission email: {str(e)}")
        return False, f"Failed to send email: {str(e)}"


def send_password_reset_email(recipient_email, username, reset_link):
    """Send password reset email"""
    try:
        config = get_email_config()
        
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "🔑 Reset Your DOLPHIN BYPASS TOOL Password"
        msg["From"] = config['sender']
        msg["To"] = recipient_email
        
        html = f"""
        <html>
            <head>
                <style>
                    body {{ font-family: 'Segoe UI', Arial, sans-serif; background-color: #f4f4f4; padding: 20px; }}
                    .container {{ max-width: 600px; margin: 0 auto; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 3px; border-radius: 12px; }}
                    .content {{ background-color: white; padding: 30px; border-radius: 10px; }}
                    h1 {{ color: #333; text-align: center; margin-bottom: 30px; }}
                    .logo {{ text-align: center; font-size: 24px; font-weight: bold; color: #0400FF; margin-bottom: 20px; }}
                    .button {{ text-align: center; margin: 30px 0; }}
                    .button a {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold; }}
                    .button a:hover {{ transform: translateY(-2px); }}
                    .link-box {{ background-color: #f5f5f5; padding: 10px; border-radius: 5px; word-break: break-all; margin: 15px 0; }}
                    .warning {{ background-color: #fff3cd; padding: 10px; border-radius: 5px; color: #856404; margin: 15px 0; }}
                    .footer {{ margin-top: 30px; text-align: center; color: #999; font-size: 12px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="content">
                        <div class="logo">🐬 DOLPHIN BYPASS TOOL</div>
                        
                        <h2>Password Reset Request</h2>
                        
                        <p>Hello <strong>{username}</strong>,</p>
                        
                        <p>We received a request to reset your password. Click the button below to set a new password:</p>
                        
                        <div class="button">
                            <a href="{reset_link}">🔑 Reset Password</a>
                        </div>
                        
                        <p>Or copy and paste this link in your browser:</p>
                        <div class="link-box">
                            <code>{reset_link}</code>
                        </div>
                        
                        <div class="warning">
                            ⚠️ <strong>This link will expire in 1 hour.</strong>
                        </div>
                        
                        <p style="margin-top: 20px; color: #666;">
                            If you did not request a password reset, please ignore this email. Your account is still secure.
                        </p>
                        
                        <hr style="margin-top: 30px; border: none; border-top: 1px solid #ddd;">
                        
                        <div class="footer">
                            <p>This is an automated message, please do not reply.</p>
                            <p>&copy; 2026 DOLPHIN BYPASS TOOL</p>
                        </div>
                    </div>
                </div>
            </body>
        </html>
        """
        
        part = MIMEText(html, "html")
        msg.attach(part)
        
        with smtplib.SMTP(config['server'], config['port']) as server:
            server.starttls()
            server.login(config['sender'], config['password'])
            server.sendmail(config['sender'], recipient_email, msg.as_string())
        
        logger.info(f"✅ Password reset email sent to {recipient_email}")
        return True, "Reset email sent successfully"
    
    except Exception as e:
        logger.error(f"❌ Error sending reset email: {str(e)}")
        return False, f"Failed to send email: {str(e)}"


def send_license_expiry_warning(recipient_email, username, admission_number, days_until_expiry, license_type):
    """Send email warning about upcoming license expiry"""
    try:
        config = get_email_config()
        
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"⚠️ Your {license_type} License Expires in {days_until_expiry} Days"
        msg["From"] = config['sender']
        msg["To"] = recipient_email
        
        urgency = "critical" if days_until_expiry <= 7 else "warning"
        
        html = f"""
        <html>
            <head>
                <style>
                    body {{ font-family: 'Segoe UI', Arial, sans-serif; background-color: #f4f4f4; padding: 20px; }}
                    .container {{ max-width: 600px; margin: 0 auto; background: linear-gradient(135deg, #ff9800 0%, #f44336 100%); padding: 3px; border-radius: 12px; }}
                    .content {{ background-color: white; padding: 30px; border-radius: 10px; }}
                    h1 {{ color: #333; text-align: center; margin-bottom: 30px; }}
                    .logo {{ text-align: center; font-size: 24px; font-weight: bold; color: #0400FF; margin-bottom: 20px; }}
                    .warning-box {{ background-color: #fff3e0; padding: 20px; border-left: 4px solid #ff9800; margin: 20px 0; }}
                    .critical-box {{ background-color: #ffebee; padding: 20px; border-left: 4px solid #f44336; margin: 20px 0; }}
                    .license-badge {{ display: inline-block; padding: 5px 10px; border-radius: 5px; font-weight: bold; }}
                    .license-fair {{ background: #ffd700; color: #000; }}
                    .license-good {{ background: #4CAF50; color: white; }}
                    .license-excellent {{ background: #9c27b0; color: white; }}
                    .footer {{ margin-top: 30px; text-align: center; color: #999; font-size: 12px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="content">
                        <div class="logo">🐬 DOLPHIN BYPASS TOOL</div>
                        
                        <h2 style="color: {'#f44336' if days_until_expiry <= 7 else '#ff9800'};">
                            {'⚠️ CRITICAL' if days_until_expiry <= 7 else '⚠️ Warning'}
                        </h2>
                        
                        <p>Hello <strong>{username}</strong>,</p>
                        
                        <div class="{ 'critical-box' if days_until_expiry <= 7 else 'warning-box' }">
                            <h3 style="margin-top: 0;">Your License is Expiring Soon!</h3>
                            <p style="font-size: 18px; margin: 10px 0;">
                                Your <strong>{license_type}</strong> license will expire in 
                                <strong style="color: {'#f44336' if days_until_expiry <= 7 else '#ff9800'};">
                                    {days_until_expiry} days
                                </strong>.
                            </p>
                        </div>
                        
                        <div style="background-color: #f9f9f9; padding: 15px; border-radius: 5px; margin: 20px 0;">
                            <p><strong>Account Details:</strong></p>
                            <p>Username: {username}</p>
                            <p>Email: {recipient_email}</p>
                            <p>Admission Number: {admission_number}</p>
                            <p>License Type: <span class="license-badge license-{license_type.lower()}">{license_type}</span></p>
                        </div>
                        
                        <p style="margin-top: 20px;">
                            After expiry, you will lose access to the tool. Please renew your license to continue using DOLPHIN BYPASS TOOL.
                        </p>
                        
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="https://my-dolphin-tool.onrender.com/dashboard" 
                               style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">
                                Renew License
                            </a>
                        </div>
                        
                        <hr style="margin-top: 30px; border: none; border-top: 1px solid #ddd;">
                        
                        <div class="footer">
                            <p>This is an automated message, please do not reply.</p>
                            <p>&copy; 2026 DOLPHIN BYPASS TOOL</p>
                        </div>
                    </div>
                </div>
            </body>
        </html>
        """
        
        part = MIMEText(html, "html")
        msg.attach(part)
        
        with smtplib.SMTP(config['server'], config['port']) as server:
            server.starttls()
            server.login(config['sender'], config['password'])
            server.sendmail(config['sender'], recipient_email, msg.as_string())
        
        logger.info(f"✅ License expiry warning sent to {recipient_email}")
        return True, "Warning email sent successfully"
    
    except Exception as e:
        logger.error(f"❌ Error sending warning email: {str(e)}")
        return False, f"Failed to send email: {str(e)}"