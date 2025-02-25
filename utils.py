# utils.py
from flask import jsonify
from sib_api_v3_sdk import Configuration, ApiClient, TransactionalEmailsApi
from sib_api_v3_sdk.models.send_smtp_email import SendSmtpEmail
import os

def send_reset_email(email, name, token):
    sender_email = os.getenv('SENDER_EMAIL')
    sendinblue_api_key = os.getenv('SENDINBLUE_API_KEY')
    configuration = Configuration()
    configuration.api_key['api-key'] = sendinblue_api_key
    api_instance = TransactionalEmailsApi(ApiClient(configuration))
    to = [{'email': email}]
    subject = "Password Reset Request"
    html_content = f"""
    <p>Hi {name},</p>
    <p>To reset your password, click the link below:</p>
    <p><a href='http://localhost:5173/reset-password/{token}'>Reset Password</a></p>
    <p>If you didn't request this, ignore this email.</p>
    """
    send_smtp_email = SendSmtpEmail(sender={'email': sender_email}, to=to, subject=subject, html_content=html_content)
    try:
        api_instance.send_transac_email(send_smtp_email)
    except Exception as e:
        raise e