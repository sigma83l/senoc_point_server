from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from flask_mail import Mail, Message
from dotenv import load_dotenv

import stripe
import os
import random
import time

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL').replace("mysql://", "mysql+pymysql://")
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.secret_key = os.getenv('SECRET_KEY')

OTP_EXPIRY_TIME = 300
OTP_REQUEST_LIMIT = 60

db = SQLAlchemy(app)
jwt = JWTManager(app)
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
mail = Mail(app)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    price = db.Column(db.Float, nullable=False)
    reviews = db.relationship('Review', backref='product', lazy=True)

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text, nullable=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)

@app.route('/email_test', methods=['GET'])
def email_test():
    email = "test@example.com"
    send_email('hamedsedaghatqrpr83@gmail.com', 'templates/payment_notification.html', {'email': email, 'amount': amount})

    return jsonify({'message': 'Email sent successfully'})

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    new_admin = Admin(email=data['email'], password=data['password'])
    db.session.add(new_admin)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    admin = Admin.query.filter_by(email=data['email']).first()
    if admin and admin.password == data['password']:
        access_token = create_access_token(identity=admin.email)
        return jsonify({'access_token': access_token})
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/products', methods=['GET'])
def get_products():
    products = Product.query.all()
    return jsonify([{'id': p.id, 'name': p.name, 'price': p.price} for p in products])

@app.route('/product/<int:id>', methods=['POST'])
def get_products_by_id(id):
    product = Product.query.where({id})
    return jsonify({'id': product.id, 'name': product.name, 'price': product.price})

@app.route('/add-product', methods=['POST'])
@jwt_required()
def create_product():
    data = request.get_json()
    new_product = Product(name=data['name'], price=data['price'])
    db.session.add(new_product)
    db.session.commit()
    return jsonify({'message': 'Product created successfully'})

@app.route('/update-product/<int:id>', methods=['PUT'])
@jwt_required()
def update_product(id):
    data = request.get_json()
    product = Product.query.get_or_404(id)
    product.name = data['name']
    product.price = data['price']
    db.session.commit()
    return jsonify({'message': 'Product updated successfully'})

@app.route('/delete-product/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_product(id):
    product = Product.query.get_or_404(id)
    db.session.delete(product)
    db.session.commit()
    return jsonify({'message': 'Product deleted successfully'})

@app.route('/add-review/<int:product_id>', methods=['POST'])
@jwt_required()
def add_review(product_id):
    data = request.get_json()
    new_review = Review(product_id=product_id, admin_id=data['admin_id'], rating=data['rating'], comment=data['comment'])
    db.session.add(new_review)
    db.session.commit()
    return jsonify({'message': 'Review added successfully'})

@app.route('/delete-review/<int:review_id>', methods=['DELETE'])
@jwt_required()
def delete_review(review_id):
    review = Review.query.get_or_404(review_id)
    db.session.delete(review)
    db.session.commit()
    return jsonify({'message': 'Review deleted successfully'})

@app.route('/update-review/<int:review_id>', methods=['PUT'])
@jwt_required()
def update_review(review_id):
    data = request.get_json()
    review = Review.query.get_or_404(review_id)
    review.rating = data['rating']
    review.comment = data['comment']
    db.session.commit()
    return jsonify({'message': 'Review updated successfully'})

@app.route('/reviews/<int:product_id>', methods=['GET'])
def get_reviews(product_id):
    reviews = Review.query.filter_by(product_id=product_id).all()
    return jsonify([{'id': r.id, 'admin_id': r.admin_id, 'rating': r.rating, 'comment': r.comment} for r in reviews])

# @app.route('/request-otp', methods=['POST'])
# def request_otp():
#     data = request.get_json()
#     otp = random.randint(100000, 999999)
#     session['otp'] = otp
#     session['otp_email'] = data['email']
#     send_email(data['email'], 'templates/otp_email.html', {'otp': otp})
#     return jsonify({'message': 'OTP sent to email'})

@app.route('/pay', methods=['POST'])
def pay():
    data = request.get_json()

    if not data or 'otp' not in data or 'amount' not in data or 'token' not in data:
        return jsonify({'message': 'Missing required fields'}), 400

    email = data.get('email')
    otp = data.get('otp')
    amount = data.get('amount')
    token = data.get('token')

    if not email or session.get('otp_email') != email or session.get('otp') != otp:
        return jsonify({'message': 'Invalid OTP'}), 400

    try:
        amount_cents = int(float(amount) * 100)
        if amount_cents <= 0:
            return jsonify({'message': 'Invalid amount'}), 400
    except ValueError:
        return jsonify({'message': 'Invalid amount format'}), 400

    try:
        charge = stripe.Charge.create(
            amount=amount_cents,
            currency='usd',
            source=token,
            description='Product Purchase'
        )

        send_email(email, 'templates/payment_success.html', {'email': email, 'amount': amount})
        send_email('hamedsedaghatqrpr83@gmail.com', 'templates/payment_notification.html', {'email': email, 'amount': amount})

        return jsonify({'message': 'Payment successful', 'charge_id': charge.id})

    except stripe.error.StripeError as e:
        return jsonify({'message': 'Payment failed', 'error': str(e)}), 500


def send_email(recipient, template_path, context):
    with open(template_path) as f:
        template = f.read()
    body = template.format(**context)
    msg = Message('Payment Confirmation', sender=app.config['MAIL_USERNAME'], recipients=[recipient])
    msg.html = body
    mail.send(msg)

@app.route('/request-otp', methods=['POST'])
def request_otp():
    data = request.get_json()
    email = data.get('email')
    current_time = time.time()
    
    if 'otp_timestamp' in session and current_time - session['otp_timestamp'] < OTP_REQUEST_LIMIT:
        return jsonify({'message': 'Please wait before requesting another OTP'}), 429
    
    otp = random.randint(100000, 999999)
    session['otp'] = otp
    session['otp_email'] = email
    session['otp_timestamp'] = current_time
    session['otp_expiry'] = current_time + OTP_EXPIRY_TIME
    
    send_email(email, 'templates/otp_email.html', {'otp': otp})
    return jsonify({'message': 'OTP sent to email'})

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')
    current_time = time.time()
    
    if 'otp' not in session or 'otp_expiry' not in session:
        return jsonify({'message': 'OTP not found, please request a new one'}), 400
    
    if session['otp_email'] != email:
        return jsonify({'message': 'Invalid email'}), 400
    
    if current_time > session['otp_expiry']:
        session.pop('otp', None)
        session.pop('otp_email', None)
        session.pop('otp_expiry', None)
        return jsonify({'message': 'OTP expired, please request a new one'}), 400
    
    if session['otp'] != otp:
        return jsonify({'message': 'Invalid OTP'}), 400
    
    session.pop('otp', None)
    session.pop('otp_email', None)
    session.pop('otp_expiry', None)
    return jsonify({'message': 'OTP verified successfully'})

if __name__ == '__main__':
    app.run(debug=True)
