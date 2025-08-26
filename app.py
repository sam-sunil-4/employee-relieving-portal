from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import boto3
import requests
import os
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth
import logging
import secrets 

ALLOWED_EMAILS = [email.strip().lower() for email in os.getenv("ALLOWED_EMAILS", "").split(",")]


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load environment variables
load_dotenv()
logging.info(f"Loaded secondary key: {'set' if os.getenv('secondary_aws_access_key') else 'missing'}")

# Flask app setup
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "your_strong_default_secret_key_here")
if app.secret_key == "your_strong_default_secret_key_here":
    logging.warning("FLASK_SECRET_KEY is using a default value. Please set a strong, random secret key in your .env file for production.")
logging.info(f"Flask secret key loaded: {'SET' if app.secret_key != 'your_strong_default_secret_key_here' else 'DEFAULT'}")
logging.info(f"Flask secret key length: {len(app.secret_key) if app.secret_key else 'N/A'}")

# Authlib OAuth setup
oauth = OAuth(app)

# --- Authlib Google OAuth setup ---
CONF_URL = 'https://accounts.google.com/.well-known/openid-configuration'

oauth.register(
    name='google',
    server_metadata_url=CONF_URL,
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    client_kwargs={
        'scope': 'openid email profile',
        'prompt': 'select_account'
    }
)

# AWS credentials
PRIMARY_CREDENTIALS = {
    'aws_access_key_id': os.getenv('primary_aws_access_key'),
    'aws_secret_access_key': os.getenv('primary_aws_secret_key')
}

SECONDARY_CREDENTIALS = {
    'aws_access_key_id': os.getenv('secondary_aws_access_key'),
    'aws_secret_access_key': os.getenv('secondary_aws_secret_key')
}

# --- Authentication Routes ---
@app.route("/login")
def login():
    redirect_uri = url_for('authorized', _external=True)
    
    nonce = secrets.token_hex(16) 
    session['oauth_nonce'] = nonce 

    return oauth.google.authorize_redirect(redirect_uri, nonce=nonce)

@app.route("/logout")
def logout():
    session.clear()
    logging.info("User logged out.")
    return redirect(url_for("form"))


@app.route("/login/authorized")

def authorized():
    try:
        token = oauth.google.authorize_access_token()

        expected_nonce = session.pop('oauth_nonce', None)
 
        

        if not expected_nonce:
            logging.error("Security warning: Nonce not found in session for validation.")
            raise ValueError("Authentication failed: Nonce missing from session.")

        userinfo = oauth.google.parse_id_token(token, nonce=expected_nonce)

        session['email'] = userinfo['email']
        logging.info(f"User {session['email']} successfully authenticated with Google.")

        if not session['email'].endswith('@qburst.com') or session['email'].lower() not in ALLOWED_EMAILS:
            session.clear()
            logging.warning(f"Unauthorized login attempt by {userinfo['email']}. Session cleared.")
            return "Unauthorized access."
        
        if not session['email'].endswith('@qburst.com'):
            session.clear()
            logging.warning(f"Unauthorized login attempt by {userinfo['email']}. Session cleared.")
            return "Unauthorized access. Only @qburst.com emails are allowed."

        return redirect(url_for("form"))

    except Exception as e:
        logging.error(f"OAuth authorization failed: {e}", exc_info=True)
        session.clear()
        return "Access denied or an error occurred during login. Please try again."
    
# --- App Routes ---
@app.route("/")
def form():
    if 'email' not in session:
        return redirect(url_for('login'))
    return render_template('form.html')

def get_iam_client(account="primary"):
    """
    Initializes and returns an AWS IAM client for the specified account.
    """
    key = None
    secret = None
    region = None

    if account == "primary":
        key = os.getenv('primary_aws_access_key')
        secret = os.getenv('primary_aws_secret_key')
        region = os.getenv('primary_aws_region')
    elif account == "secondary":
        key = os.getenv('secondary_aws_access_key')
        secret = os.getenv('secondary_aws_secret_key')
        region = os.getenv('secondary_aws_region') 
    else:
        logging.error(f"Unknown account type: {account}")
        return None

    logging.debug(f"IAM credentials for {account} -> key={'set' if key else 'missing'}, secret={'set' if secret else 'missing'}, region={region}")

    if not key or not secret or not region:
        logging.error(f"Missing credentials or region for {account} account. {key} , {secret} , {region}")
        return None

    try:
        return boto3.client(
            'iam',
            aws_access_key_id=key,
            aws_secret_access_key=secret,
            region_name=region
        )
    except Exception as e:
        logging.error(f"Failed to create IAM client for {account}: {e}", exc_info=True)
        return None

@app.route('/check', methods=['POST'])
def check_email():
    """
    Checks the existence of emails across AWS, GitLab, and Azure.
    Requires user to be logged in.
    """
    if 'email' not in session:
        return jsonify({"error": "Unauthorized. Please log in."}), 401

    email_input_raw = request.form.get('emails')
    email_list = parse_emails(email_input_raw)

    aws_results = {}
    gitlab_results = {}
    azure_results = {}

    for email_to_check in email_list:
        aws_results[email_to_check] = aws_check(email_to_check)
        gitlab_results[email_to_check] = gitlab_check(email_to_check)
        azure_results[email_to_check] = azure_check(email_to_check)

    return render_template('result.html',
                           results=aws_results,
                           gitlab_results=gitlab_results,
                           azure_results=azure_results)

def parse_emails(raw_input):
    """
    Parses a raw string of emails, splitting by comma or newline.
    """
    return [email.strip() for email in raw_input.replace(",", '\n').split('\n') if email.strip()]

def aws_check(email):
    """
    Checks if an email (as a username) exists in AWS IAM for primary and secondary accounts.
    """
    results = {}

    for label, account_type in [("Primary", "primary"), ("Secondary", "secondary")]:
        iam = get_iam_client(account_type)
        if iam is None:
            results[label] = "❌ Error (Client Init)"
            continue

        try:
            paginator = iam.get_paginator("list_users")
            found = False

            for page in paginator.paginate():
                for user in page["Users"]:
                    if user["UserName"].lower() == email.lower():
                        results[label] = "✅ Found"
                        found = True
                        break
                if found:
                    break

            if not found:
                results[label] = "❌ Not Found"

        except Exception as e:
            logging.error(f"{label} AWS Check Error for {email}: {e}", exc_info=True)
            results[label] = "❌ Error"

    return results

def gitlab_check(email):
    """
    Checks if an email exists as a user in GitLab.
    """
    GITLAB_URL = os.getenv('GITLAB_URL')
    PAT = os.getenv('PAT') # Personal Access Token

    if not GITLAB_URL or not PAT:
        logging.error("Missing GITLAB_URL or PAT environment variables.")
        return "❌ Error (Config)"

    try:
        headers = {
            "PRIVATE-TOKEN": PAT
        }

        search_url = f"{GITLAB_URL}/api/v4/users?search={email}"
        response = requests.get(search_url, headers=headers)

        if response.status_code == 200:
            users = response.json()
            for user in users:
                if user.get("email", "").strip().lower() == email.strip().lower() or \
                   user.get("username", "").strip().lower() == email.strip().lower():
                    return "✅ Found"
            return "❌ Not Found"
        elif response.status_code == 401:
            logging.error(f"GitLab API Unauthorized: Check PAT. Status: {response.status_code} -> {response.text}")
            return "❌ Error (Unauthorized)"
        else:
            logging.error(f"GitLab API Error: {response.status_code} -> {response.text}")
            return "❌ Error"

    except requests.exceptions.RequestException as re:
        logging.error(f"GitLab Network Error: {re}", exc_info=True)
        return "❌ Error (Network)"
    except Exception as ge:
        logging.error(f"Unexpected GitLab Error: {ge}", exc_info=True)
        return "❌ Error (Unexpected)"

def get_azure_access_token():
    """
    Obtains an access token for Azure AD Graph API using client credentials.
    """
    tenant_id = os.getenv('AZURE_TENANT_ID')
    client_id = os.getenv('AZURE_CLIENT_ID')
    client_secret = os.getenv('AZURE_CLIENT_SECRET')

    if not tenant_id or not client_id or not client_secret:
        logging.error("Missing AZURE_TENANT_ID, AZURE_CLIENT_ID, or AZURE_CLIENT_SECRET environment variables.")
        return None

    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    data = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': 'https://graph.microsoft.com/.default' # Scope for Microsoft Graph API
    }

    try:
        response = requests.post(url, headers=headers, data=data)
        if response.status_code == 200:
            return response.json().get("access_token")
        else:
            logging.error(f"Failed to get Azure access token: {response.status_code} -> {response.text}")
            return None
    except requests.exceptions.RequestException as re:
        logging.error(f"Azure Token Network Error: {re}", exc_info=True)
        return None
    except Exception as e:
        logging.error(f"Unexpected Azure Token Error: {e}", exc_info=True)
        return None

def azure_check(email):
    """
    Checks if an email exists as a user in Azure Active Directory (Microsoft Graph API).
    """
    token = get_azure_access_token()
    if not token:
        return "❌ Error (Token Not Received)"

    headers = {
        'Authorization': f"Bearer {token}",
        'Content-Type': 'application/json'
    }

    try:
        response = requests.get(
            f"https://graph.microsoft.com/v1.0/users/{email}",
            headers=headers
        )

        if response.status_code == 200:
            return "✅ Found"
        elif response.status_code == 404:
            return "❌ Not Found"
        elif response.status_code == 403:
            logging.error(f"Azure API Forbidden: Check permissions for the AAD app. Status: {response.status_code} -> {response.text}")
            return "❌ Error (Forbidden)"
        else:
            logging.error(f"Azure API Error for {email}: {response.status_code} -> {response.text}")
            return "❌ Error"
    except requests.exceptions.RequestException as re:
        logging.error(f"Azure Network Error: {re}", exc_info=True)
        return "❌ Error (Network)"
    except Exception as e:
        logging.error(f"Unexpected Azure Check Error: {e}", exc_info=True)
        return "❌ Exception Occurred"

@app.route("/delete", methods=["POST"])
def delete_user():
    """
    Deletes an AWS IAM user and all associated resources.
    Requires user to be logged in.
    """
    if 'email' not in session:
        return jsonify({"success": False, "message": "Unauthorized. Please log in."}), 401

    data = request.get_json()
    email = data.get("email")
    account = data.get("account") 

    if not email or not account:
        return jsonify({"success": False, "message": "Missing email or account type."}), 400

    iam = get_iam_client(account)
    if iam is None:
        return jsonify({"success": False, "message": f"❌ Failed to get IAM client for {account}."}), 500

    try:
        logging.info(f"Attempting to delete IAM user {email} from {account} account.")

        # Detach managed policies
        for policy in iam.list_attached_user_policies(UserName=email)['AttachedPolicies']:
            iam.detach_user_policy(UserName=email, PolicyArn=policy['PolicyArn'])
            logging.info(f"Detached policy {policy['PolicyArn']} from user {email}.")

        # Delete inline policies
        for policy_name in iam.list_user_policies(UserName=email)['PolicyNames']:
            iam.delete_user_policy(UserName=email, PolicyName=policy_name)
            logging.info(f"Deleted inline policy {policy_name} from user {email}.")

        # Remove from groups
        for group in iam.list_groups_for_user(UserName=email)['Groups']:
            iam.remove_user_from_group(UserName=email, GroupName=group['GroupName'])
            logging.info(f"Removed user {email} from group {group['GroupName']}.")

        # Delete access keys
        for key in iam.list_access_keys(UserName=email)['AccessKeyMetadata']:
            iam.delete_access_key(UserName=email, AccessKeyId=key['AccessKeyId'])
            logging.info(f"Deleted access key {key['AccessKeyId']} for user {email}.")

        # Delete login profile (if exists)
        try:
            iam.delete_login_profile(UserName=email)
            logging.info(f"Deleted login profile for user {email}.")
        except iam.exceptions.NoSuchEntityException:
            logging.info(f"No login profile found for user {email}.")
            pass # No login profile to delete

        # Delete signing certificates
        for cert in iam.list_signing_certificates(UserName=email)['Certificates']:
            iam.delete_signing_certificate(UserName=email, CertificateId=cert['CertificateId'])
            logging.info(f"Deleted signing certificate {cert['CertificateId']} for user {email}.")

        # Delete MFA devices
        for mfa in iam.list_mfa_devices(UserName=email)['MFADevices']:
            iam.deactivate_mfa_device(UserName=email, SerialNumber=mfa['SerialNumber'])
            logging.info(f"Deactivated MFA device {mfa['SerialNumber']} for user {email}.")

        # Finally delete user
        iam.delete_user(UserName=email)
        logging.info(f"Successfully deleted IAM user {email} from {account} account.")

        return jsonify({"success": True, "message": f"✅ {account.capitalize()} user {email} deleted successfully."})

    except iam.exceptions.NoSuchEntityException:
        logging.warning(f"IAM user {email} not found in {account} account for deletion attempt.")
        return jsonify({"success": False, "message": f"❌ User {email} not found in {account}."}), 404
    except Exception as e:
        logging.error(f"Failed to delete IAM user {email} from {account}: {e}", exc_info=True)
        return jsonify({"success": False, "message": f"❌ Failed to delete {email} from {account}: {str(e)}."}), 500

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=False)