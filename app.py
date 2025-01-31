from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from flask_mail import Mail, Message
import stripe
import os
import random

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.secret_key = os.getenv('SECRET_KEY')

db = SQLAlchemy(app)
jwt = JWTManager(app)
mail = Mail(app)
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    price = db.Column(db.Float, nullable=False)
    reviews = db.relationship('Review', backref='product', lazy=True)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    cart = db.relationship('Cart', backref='user', lazy=True)

class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text, nullable=True)

# @app.route('/register', methods=['POST'])
# def register():
#     data = request.get_json()
#     new_user = User(email=data['email'], password=data['password'])
#     db.session.add(new_user)
#     db.session.commit()
#     return jsonify({'message': 'User registered successfully'})

# @app.route('/login', methods=['POST'])
# def login():
#     data = request.get_json()
#     user = User.query.filter_by(email=data['email']).first()
#     if user and user.password == data['password']:
#         access_token = create_access_token(identity=user.email)
#         return jsonify({'access_token': access_token})
#     return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/products', methods=['GET'])
def get_products():
    products = Product.query.all()
    return jsonify([{'id': p.id, 'name': p.name, 'price': p.price} for p in products])

@app.route('/products', methods=['POST'])
@jwt_required()
def create_product():
    data = request.get_json()
    new_product = Product(name=data['name'], price=data['price'])
    db.session.add(new_product)
    db.session.commit()
    return jsonify({'message': 'Product created successfully'})

@app.route('/products/<int:id>', methods=['PUT'])
@jwt_required()
def update_product(id):
    data = request.get_json()
    product = Product.query.get_or_404(id)
    product.name = data['name']
    product.price = data['price']
    db.session.commit()
    return jsonify({'message': 'Product updated successfully'})

@app.route('/products/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_product(id):
    product = Product.query.get_or_404(id)
    db.session.delete(product)
    db.session.commit()
    return jsonify({'message': 'Product deleted successfully'})

@app.route('/reviews/<int:product_id>', methods=['POST'])
@jwt_required()
def add_review(product_id):
    data = request.get_json()
    new_review = Review(product_id=product_id, user_id=data['user_id'], rating=data['rating'], comment=data['comment'])
    db.session.add(new_review)
    db.session.commit()
    return jsonify({'message': 'Review added successfully'})

@app.route('/reviews/<int:review_id>', methods=['DELETE'])
@jwt_required()
def delete_review(review_id):
    review = Review.query.get_or_404(review_id)
    db.session.delete(review)
    db.session.commit()
    return jsonify({'message': 'Review deleted successfully'})

@app.route('/reviews/<int:review_id>', methods=['PUT'])
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
    return jsonify([{'id': r.id, 'user_id': r.user_id, 'rating': r.rating, 'comment': r.comment} for r in reviews])

@app.route('/request-otp', methods=['POST'])
def request_otp():
    data = request.get_json()
    otp = random.randint(100000, 999999)
    session['otp'] = otp
    session['otp_email'] = data['email']
    send_email(data['email'], 'templates/otp_email.html', {'otp': otp})
    return jsonify({'message': 'OTP sent to email'})

@app.route('/pay', methods=['POST'])
def pay():
    data = request.get_json()
    if 'otp' not in data or 'otp_email' not in session or session['otp_email'] != data['email'] or session['otp'] != data['otp']:
        return jsonify({'message': 'Invalid OTP'}), 400
    
    charge = stripe.Charge.create(
        amount=int(data['amount'] * 100),
        currency='usd',
        source=data['token'],
        description='Product Purchase'
    )
    send_email(data['email'], 'templates/payment_success.html', {'email': data['email'], 'amount': data['amount']})
    send_email('hamedsedaghatqrpr83@gmail.com', 'templates/payment_notification.html', {'email': data['email'], 'amount': data['amount']})
    return jsonify({'message': 'Payment successful'})

def send_email(recipient, template_path, context):
    with open(template_path) as f:
        template = f.read()
    body = template.format(**context)
    msg = Message('Payment Confirmation', sender=app.config['MAIL_USERNAME'], recipients=[recipient])
    msg.html = body
    mail.send(msg)

if __name__ == '__main__':
    app.run(debug=True)
