from flask import Flask, render_template, request
import hashlib
import requests
import math
import string
import random

app = Flask(__name__)

# ------------------ Helper Functions ------------------

def calculate_entropy(password):
    charset = 0
    if any(c.islower() for c in password): charset += 26
    if any(c.isupper() for c in password): charset += 26
    if any(c.isdigit() for c in password): charset += 10
    if any(c in string.punctuation for c in password): charset += 32

    if charset == 0:
        return 0
    return round(len(password) * math.log2(charset), 2)


def estimate_crack_time(entropy):
    guesses = 2 ** entropy
    attack_speed = 1e9  # 1 billion guesses/sec
    seconds = guesses / attack_speed
    return seconds


def format_crack_time(seconds):
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.2f} minutes"
    elif seconds < 86400:
        return f"{seconds/3600:.2f} hours"
    elif seconds < 31536000:
        return f"{seconds/86400:.2f} days"
    else:
        return f"{seconds/31536000:.2f} years"


def check_pwned(password):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    try:
        response = requests.get(url, timeout=5)
        hashes = (line.split(":") for line in response.text.splitlines())

        for h, count in hashes:
            if h == suffix:
                return int(count)

    except Exception as e:
        print("Error:", e)
        return 0

    return 0


# ------------------ Password Generator ------------------

def generate_password(length=12):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))


# ------------------ Routes ------------------

@app.route('/')
def home():
    return render_template("home.html")   # FIXED (your home page name)


@app.route('/dashboard')
def dashboard():
    return render_template("dashboard.html")


@app.route('/analyser', methods=['GET','POST'])
def analyser():
    password = ""
    entropy = 0
    crack_time = "0 seconds"
    breach_count = 0
    strength_percent = 0

    if request.method == 'POST':
        password = request.form['password']

        entropy = calculate_entropy(password)
        crack_seconds = estimate_crack_time(entropy)
        crack_time = format_crack_time(crack_seconds)
        breach_count = check_pwned(password)

        # Normalize to 0–100
        strength_percent = min(int(entropy), 100)

    return render_template("analyser.html",
                           password=password,
                           entropy=entropy,
                           crack_time=crack_time,
                           breach_count=breach_count,
                           strength_percent=strength_percent)


@app.route('/breach', methods=['GET','POST'])
def breach():

    result = None

    if request.method == 'POST':
        password = request.form['password']
        count = check_pwned(password)

        if count:
            result = f"⚠ Password found in {count} breaches!"
        else:
            result = "✅ Password not found in breach database."

    return render_template("breach.html", result=result)


@app.route('/generator')
def generator():
    password = generate_password()
    return render_template("generator.html", password=password)


@app.route('/tips')
def tips():
    return render_template("tips.html")


# ------------------ Run App ------------------

if __name__ == '__main__':
    app.run(debug=True)