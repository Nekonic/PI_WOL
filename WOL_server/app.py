from flask import Flask, request, render_template, redirect, url_for, session, abort
import ssl
import subprocess
from functools import wraps
from datetime import timedelta


app = Flask(__name__)
app.secret_key = 'NET100'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=1)

# password setting
PASSWORD = 'suck!HOJE*396'

# Save login attempts by IP
login_attempts = {}

# IP block list
banned_ips = set()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def block_banned_ips():
    client_ip = request.remote_addr
    if client_ip in banned_ips:
        abort(403)  # Forbidden

def before_request():
    session.modified = True  # update
    if 'logged_in' in session and not session.permanent:
        # When a session expires
        session.pop('logged_in', None)
        return redirect(url_for('login'))


@app.route('/', methods=['GET', 'POST'])
def login():
    client_ip = request.remote_addr

    if request.method == 'POST':
        if client_ip in banned_ips:
            abort(403)  # blocked

        password = request.form.get('password')
        if password == PASSWORD:
            # Save login state in session on successful login
            session['logged_in'] = True
            # Reset login attempt count
            login_attempts.pop(client_ip, None)
            return redirect(url_for('button_page'))
        else:
            # Increase the number of attempts on failed logins
            attempts = login_attempts.get(client_ip, 0) + 1
            login_attempts[client_ip] = attempts
            if attempts >= 3:
                banned_ips.add(client_ip)
                abort(403)  # blocked
            return render_template('login.html', error='Invalid password.')

    return render_template('login.html')




@app.route('/button', methods=['GET', 'POST'])
@login_required
def button_page():
    if request.method == 'POST':
        subprocess.run(['./WOL_desktop.sh'])
        return 'Script has been executed.'
    return render_template('button.html')

if __name__ == '__main__':
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context = ('cert.pem', 'key.pem')
    app.run(host='0.0.0.0', port=443, ssl_context=context)
