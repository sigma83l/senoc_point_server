from flask import Flask, request, jsonify, session
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, verify_jwt_in_request, create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jwt, unset_jwt_cookies, set_access_cookies, set_refresh_cookies, decode_token
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
from dotenv import load_dotenv
from jinja2 import Template
from werkzeug.exceptions import Unauthorized
import datetime
from datetime import timezone
from flask import jsonify, make_response
from google.cloud import storage
import uuid
from flask_cors import CORS


import stripe
import os
import random
import time

load_dotenv()

app = Flask(__name__)
database_url = os.getenv("DATABASE_URL", "")
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
print(os.getenv('DATABASE_URL').replace("mysql://", "mysql+pymysql://"))
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config["JWT_COOKIE_CSRF_PROTECT"] = False  
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config["REFRESH_SECRET_KEY"] = os.getenv("REFRESH_SECRET_KEY") 
app.secret_key = os.getenv('SECRET_KEY')

os.environ["GOOGLE_APPLICATION_CREDENTIALS"] =  os.getenv("GCS")
storage_client = storage.Client()
bucket_name = "senoc_bucket"
bucket = storage_client.get_bucket(bucket_name)
CORS(app, supports_credentials=True, origins=["https://senocmarketing.com"])

UPLOAD_FOLDER = 'static/uploads/products'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
OTP_EXPIRY_TIME = 300
OTP_REQUEST_LIMIT = 60

db = SQLAlchemy(app)
jwt = JWTManager(app)
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
mail = Mail(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt()

otp_store = {}

class Brand(db.Model):
    __tablename__ = 'brand'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)

    def to_dict(self):
        return {"id": self.id, "name": self.name}

class Category(db.Model):
    __tablename__ = 'category'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)

    def to_dict(self):
        return {"id": self.id, "name": self.name}

class Product(db.Model):
    __tablename__ = 'product'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    price = db.Column(db.Float, nullable=False)
    inventory = db.Column(db.Integer, nullable=False)
    
    brand_id = db.Column(db.Integer, db.ForeignKey('brand.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)

    brand = db.relationship('Brand', backref='products')
    category = db.relationship('Category', backref='products')

    main_image = db.Column(db.String(255), nullable=False)
    additional_images = db.Column(db.JSON, nullable=True)

    hours = db.Column(db.Float, nullable=False)
    serial_number = db.Column(db.String(50), unique=True, nullable=False)

    reviews = db.relationship('Review', backref='product', lazy=True)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "price": self.price,
            "brand": self.brand.to_dict() if self.brand else None,
            "category": self.category.to_dict() if self.category else None,
            "main_image": self.main_image,
            "additional_images": self.additional_images or [],
            "hours": self.hours,
            "serial_number": self.serial_number,
            "reviews": [review.to_dict() for review in self.reviews]
        }

class User(db.Model):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    reviews = db.relationship('Review', backref='user', lazy=True)
    role = db.Column(db.String(10), default="user") 

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "role": self.role
        }

class Cart(db.Model):
    __tablename__ = 'cart'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date_of_order = db.Column(db.DateTime, default=db.func.current_timestamp())  
    is_delivered = db.Column(db.Boolean, default=False)
    progress = db.Column(db.Integer, default=0)

    user = db.relationship('User', backref='carts')
    items = db.relationship('CartItem', backref='cart', lazy=True, cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "user": self.user.to_dict() if self.user else None,
            "items": [item.to_dict() for item in self.items],
            "date_of_order": self.date_of_order.strftime('%Y-%m-%d %H:%M:%S') if self.date_of_order else None,
            "is_delivered": self.is_delivered,
            "progress": self.progress
        }


class CartItem(db.Model):
    __tablename__ = 'cart_item'

    id = db.Column(db.Integer, primary_key=True)
    cart_id = db.Column(db.Integer, db.ForeignKey('cart.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)

    product = db.relationship('Product', backref='cart_items')

    def to_dict(self):
        return {
            "id": self.id,
            "product": self.product.to_dict() if self.product else None,
            "quantity": self.quantity
        }

class Review(db.Model):
    __tablename__ = 'review'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "rating": self.rating,
            "comment": self.comment,
            "product_id": self.product_id,
            "user_id": self.user_id
        }

# @app.route('/email_test', methods=['GET'])
# def email_test():
#     with open(template_path, 'r', encoding='utf-8') as f:
#         template_content = f.read()
    
#     # Render using Jinja2
#     template = Template(template_content)
#     body = template.render(context)
    
#     # Send email (Assuming you have an email sending function)
#     print(body)  # Debugging: Print the rendered email body

@app.before_request
def check_and_refresh_token():
    access_token = request.cookies.get('access_token_cookie')
    refresh_token = request.cookies.get('refresh_token_cookie')

    if not access_token and not refresh_token:
        return jsonify({"msg": "Missing tokens"}), 401

    try:
        # Verify JWT using cookies instead of Authorization header
        verify_jwt_in_request(locations=["cookies"])
    except Unauthorized:
        if refresh_token:
            return refresh_access_token()
        return jsonify({"msg": "Invalid or expired token"}), 401


def refresh_access_token():
    """Refresh the access token using the refresh token stored in cookies."""
    refresh_token = request.cookies.get('refresh_token_cookie')

    if not refresh_token:
        return jsonify({"msg": "Missing refresh token"}), 401

    try:
        decoded = decode_token(refresh_token)
        identity = decoded['sub']
        new_access_token = create_access_token(identity=identity)

        response = make_response(jsonify({"msg": "Access token refreshed"}))
        set_access_cookies(response, new_access_token)  # Set the new token in cookies

        return response
    except:
        return jsonify({"msg": "Invalid refresh token"}), 401

def delete_from_gcs(image_url):
    """Deletes an image from GCS based on its URL"""
    if not image_url:
        return
    
    try:
        
        object_name = image_url.split(f"{bucket_name}/")[-1]
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(object_name)
        
        if blob.exists():
            blob.delete()
            print(f"Deleted {object_name} from GCS")
    except Exception as e:
        print(f"Error deleting {object_name}: {e}")

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

def get_jwt_identity():
    jwt_data = get_jwt()
    return jwt_data.get("sub")

# def role_required(role):
#     def wrapper(fn):
#         @wraps(fn)
#         @jwt_required(locations=["cookies"]) 
#         def decorated_function(*args, **kwargs):
#             user_id = get_jwt_identity()

#             user = User.query.get(user_id)
#             print(user)

#             if not user or user.role != role:
#                 return jsonify({"error": "Access denied. Admin role is required."}), 403

#             return fn(*args, **kwargs)
#         return decorated_function
#     return wrapper

def role_required(access_level):
    """ Handles different role-based access levels dynamically. """
    def wrapper(fn):
        @wraps(fn)
        @jwt_required(locations=["cookies"])
        def decorated_function(*args, **kwargs):
            user_id = int(get_jwt_identity())
            user = User.query.get(user_id)

            if not user:
                return jsonify({"error": "Access denied. You must be logged in."}), 403

            if access_level == "user" and user.role == "admin":
                return jsonify({"error": "Access denied. Only users can access this."}), 403

            if access_level == "user_or_admin" and user.role not in ["user", "admin"]:
                return jsonify({"error": "Access denied. Only users or admins can access this."}), 403

            if access_level == "admin" and user.role != "admin":
                return jsonify({"error": "Access denied. Admin role is required."}), 403

            if access_level == "boss" and (user.role != "admin" or user.name.lower() != "boss"):
                return jsonify({"error": "Access denied. Only the boss admin can access this."}), 403

            return fn(*args, **kwargs)

        return decorated_function
    return wrapper

def verify_otp_fn(email, otp):
    otp_key = f"otp_{email}"

    if otp_key in session:
        stored_otp_data = session[otp_key]
        print(f"Real OTP: {stored_otp_data['otp']}")

        if datetime.datetime.utcnow() > stored_otp_data["expires_at"].replace(tzinfo=None):
            session.pop(otp_key, None)
            return False, "OTP expired"

        if stored_otp_data["otp"] == int(otp):
            session.pop(otp_key, None)
            return True, "OTP verified"

    return False, "Invalid OTP"

@app.route('/users/register', methods=['POST'])
def register():
    data = request.get_json()
    required_fields = ['name', 'email', 'password', 'otp']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing fields'}), 400

    otp_valid, message = verify_otp_fn(data['email'], data['otp'])
    if not otp_valid:
        return jsonify({"error": message}), 400

    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already exists'}), 400

    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(name=data['name'], email=data['email'], password=hashed_password)

    db.session.add(new_user)
    db.session.commit()

    response = make_response(jsonify({'message': 'User registered successfully'}))
    response.delete_cookie('access_token_cookie')
    response.delete_cookie('refresh_token_cookie')

    access_token =  create_access_token(identity=str(new_user.id))  
    refresh_token = create_refresh_token(identity=str(new_user.id))

    response.set_cookie('access_token_cookie', access_token, httponly=True, secure=True)
    response.set_cookie('refresh_token_cookie', refresh_token, httponly=True, secure=True)

    return response

@app.route('/users/login', methods=['POST'])
def login_user():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()

    if user and bcrypt.check_password_hash(user.password, password):
        response = make_response(jsonify({'message': 'Login successful'}))
        response.delete_cookie('access_token_cookie')
        response.delete_cookie('refresh_token_cookie')

        access_token = create_access_token(identity=str(user.id))
        refresh_token = create_refresh_token(identity=str(user.id))

        response.set_cookie('access_token_cookie', access_token, httponly=True, secure=True)
        response.set_cookie('refresh_token_cookie', refresh_token, httponly=True, secure=True)

        return response
    
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/users/<int:user_id>/make-admin", methods=["PUT"])
@role_required("boss")
def promote_to_admin(user_id):
    current_user_id = int(get_jwt_identity())
    current_user = User.query.get(current_user_id)

    if not current_user or current_user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    user.role = "admin"
    db.session.commit()

    return jsonify({"message": f"User {user_id} is now an admin!"}), 200


@app.route('/admins/login', methods=['POST'])
def login_admin():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    # Find the admin by email
    admin = User.query.filter_by(email=email, role="admin").first()

    if admin and bcrypt.check_password_hash(admin.password, password):  # Correct password check
        # Remove old cookies if present
        response = make_response(jsonify({'message': 'Login successful'}))
        response.delete_cookie('access_token_cookie')
        response.delete_cookie('refresh_token_cookie')

        # Store only admin ID as a string in JWT
        access_token = create_access_token(identity=str(admin.id))
        refresh_token = create_refresh_token(identity=str(admin.id))

        response.set_cookie('access_token_cookie', access_token, httponly=True, secure=True)
        response.set_cookie('refresh_token_cookie', refresh_token, httponly=True, secure=True)

        return response
    
    return jsonify({"error": "Invalid credentials"}), 401


@app.route('/logout', methods=['GET'])
def logout():
    response = make_response(jsonify({"message": "Logout successful"}))
    unset_jwt_cookies(response)
    return response

@app.route('/users', methods=['GET'])
@role_required("admin")
def get_users():
    users = User.query.all()
    return jsonify([user.to_dict() for user in users])

@app.route('/users', methods=['GET'])
@role_required("admin")
def get_admins():
    users = User.query.filter_by(role="admin")
    return jsonify([user.to_dict() for user in users])

@app.route('/users/<int:id>', methods=['GET'])
@role_required("user_or_admin")
def get_user(id):
    current_user_id = int(get_jwt_identity())
    if current_user_id == id:
        user = User.query.get(id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        return jsonify(user.to_dict())

@app.route('/users', methods=['PUT'])
@role_required("user")
# @jwt_required(locations=["cookies"])
def update_user():
    current_user_id = int(get_jwt_identity())
    user = User.query.get(current_user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json()
    user.name = data['name']
    if 'email' in data:
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'error': 'Email already exists'}), 400
        user.email = data['email']
    if 'password' in data:
        user.password = data['password']

    db.session.commit()
    return jsonify(user.to_dict())

@app.route('/users/<int:id>', methods=['DELETE'])
@role_required("user_or_admin")
def delete_user(id):
    print(f"DELETE request received for user {id}")  # Debugging
    current_user_id = int(get_jwt_identity())
    user_to_delete = User.query.get(id)

    if not user_to_delete:
        return jsonify({'error': 'User not found'}), 404

    current_user_data = User.query.get(current_user_id)
    
    if not current_user_data:
        return jsonify({'error': 'Unauthorized'}), 403

    if current_user_data.id == id:
        db.session.delete(user_to_delete)
        db.session.commit()
        return jsonify({'message': 'Your account has been deleted successfully'}), 200

    elif current_user_data.role == "admin":
        if current_user_data.name == "boss":
            db.session.delete(user_to_delete)
            db.session.commit()
            return jsonify({'message': 'User deleted successfully'}), 200

        elif user_to_delete.role == "user" or int(user_to_delete.id) == int(current_user_data.id):
            db.session.delete(user_to_delete)
            db.session.commit()
            return jsonify({'message': 'User deleted successfully'}), 200

        else:
            return jsonify({'error': 'Admins can only delete users or their own account'}), 403

    else:
        return jsonify({'error': 'Unauthorized action'}), 403

@app.route('/admins/<int:id>', methods=['PUT'])
@role_required("admin")
def update_admin(id):
    current_user_id = int(get_jwt_identity())
    if current_user_id != id:
        return jsonify({"message": "Unauthorized"}), 403
    admin = User.query.get(id)
    if not admin:
        return jsonify({"message": "Admin not found"}), 404

    current_user_data = User.query.filter_by(id).first()
    
    if not current_user_data:
        return jsonify({"message": "Unauthorized"}), 403

    if int(current_user_data.id) != id:
        return jsonify({"message": "You can only update your own account"}), 403

    data = request.get_json()
    if "password" not in data or not data["password"]:
        return jsonify({"message": "Password is required"}), 400

    # Update password
    admin.password = bcrypt.generate_password_hash(data["password"]).decode('utf-8')
    db.session.commit()

    return jsonify({"message": f"Password updated successfully for Admin ID {id}"}), 200

@app.route('/products', methods=['GET'])
def get_products():
    products = Product.query.all()
    return jsonify([p.to_dict() for p in products])

@app.route('/products/<int:product_id>', methods=['GET'])
def get_product_by_id(product_id):
    product = Product.query.get_or_404(product_id)
    return jsonify(product.to_dict())  # ✅ Fix applied here

@app.route('/products/by-brand/<int:brand_id>', methods=['GET'], endpoint='get_products_by_brand_unique')
def get_products_by_brand(brand_id):
    products = Product.query.filter_by(brand_id=brand_id).all()
    return jsonify([product.to_dict() for product in products])

@app.route('/products/by-category/<int:category_id>', methods=['GET'], endpoint='get_products_by_category_unique')
def get_products_by_category(category_id):
    products = Product.query.filter_by(category_id=category_id).all()
    return jsonify([product.to_dict() for product in products])

@app.route('/products', methods=['POST'])
@role_required('admin')
def create_product():
    name = request.form.get('name')
    price = request.form.get('price')
    brand_id = request.form.get('brand_id')
    category_id = request.form.get('category_id')
    inventory = request.form.get('inventory')
    hours = request.form.get('hours')
    serial_number = request.form.get('serial_number')

    if not name or not price or not hours or not serial_number:
        return jsonify({'error': 'Name, price, hours, and serial number are required'}), 400

    # Initialize image URLs
    main_image_url = None
    side_images = []

    # Process main image
    main_image = request.files.get('main_image')
    if main_image and allowed_file(main_image.filename):
        filename = f"{uuid.uuid4()}_{secure_filename(main_image.filename)}"
        blob = bucket.blob(filename)
        blob.upload_from_file(main_image)
        blob.make_public()
        main_image_url = blob.public_url
    else:
        return jsonify({'error': 'Main image is required'}), 400  # Ensure main image exists

    # Process additional images
    for image in request.files.getlist('side_images'):
        if image and allowed_file(image.filename):
            filename = f"{uuid.uuid4()}_{secure_filename(image.filename)}"
            blob = bucket.blob(filename)
            blob.upload_from_file(image)
            blob.make_public()
            side_images.append(blob.public_url)

    # Now create and commit product
    new_product = Product(
        name=name,
        price=price,
        brand_id=brand_id,
        category_id=category_id,
        hours=hours,
        inventory=inventory,
        serial_number=serial_number,
        main_image=main_image_url,  # Assign image before commit
        additional_images=side_images
    )

    db.session.add(new_product)
    db.session.commit()

    return jsonify({'message': 'Product created successfully', 'product': new_product.to_dict()}), 201


@app.route('/products/<int:product_id>', methods=['PUT'])
@role_required('admin')
def update_product(product_id):
    # Fetch the product
    product = Product.query.get(product_id)
    if not product:
        return jsonify({'error': 'Product not found'}), 404

    # Get form data
    name = request.form.get('name')
    price = request.form.get('price')
    brand_id = request.form.get('brand_id')
    category_id = request.form.get('category_id')
    hours = request.form.get('hours')
    serial_number = request.form.get('serial_number')

    # Track changes
    updated_fields = {}

    # Check for changes in text/numerical fields
    if name and name != product.name:
        updated_fields['name'] = name
    if price and price != str(product.price):
        updated_fields['price'] = price
    if brand_id and brand_id != str(product.brand_id):
        updated_fields['brand_id'] = brand_id
    if category_id and category_id != str(product.category_id):
        updated_fields['category_id'] = category_id
    if hours and hours != str(product.hours):
        updated_fields['hours'] = hours
    if serial_number and serial_number != product.serial_number:
        updated_fields['serial_number'] = serial_number

    # Handle main image update
    main_image = request.files.get('main_image')
    if main_image and allowed_file(main_image.filename):
        # Delete the old main image from the bucket if it exists
        if product.main_image:
            old_blob = bucket.blob(product.main_image.split("/")[-1])
            old_blob.delete()

        # Upload new main image
        filename = f"{uuid.uuid4()}_{secure_filename(main_image.filename)}"
        blob = bucket.blob(filename)
        blob.upload_from_file(main_image)
        blob.make_public()
        updated_fields['main_image'] = blob.public_url

    # Handle side images update
    side_images = request.files.getlist('side_images')
    if side_images and any(img.filename for img in side_images if allowed_file(img.filename)):
        # Delete old side images
        if product.additional_images:
            for old_img in product.additional_images:
                old_blob = bucket.blob(old_img.split("/")[-1])
                old_blob.delete()

        # Upload new side images
        new_side_images = []
        for image in side_images:
            if image and allowed_file(image.filename):
                filename = f"{uuid.uuid4()}_{secure_filename(image.filename)}"
                blob = bucket.blob(filename)
                blob.upload_from_file(image)
                blob.make_public()
                new_side_images.append(blob.public_url)

        updated_fields['additional_images'] = new_side_images

    # Apply updates only if there are changes
    if updated_fields:
        for field, value in updated_fields.items():
            setattr(product, field, value)
        db.session.commit()

        return jsonify({'message': 'Product updated successfully', 'updated_fields': updated_fields}), 200

    return jsonify({'message': 'No changes made'}), 200

@app.route('/products/<int:id>', methods=['DELETE'])
@role_required("admin") 
def delete_product(id):
    product = Product.query.get_or_404(id)

    delete_from_gcs(product.main_image)

    if product.additional_images:
        for image_url in product.additional_images:
            delete_from_gcs(image_url)

    db.session.delete(product)
    db.session.commit()

    return jsonify({'message': 'Product deleted successfully'})

@app.route("/products/category/<int:category_id>", methods=["GET"])
def get_products_by_category(category_id):
    products = Product.query.filter_by(category_id=category_id).all()
    return jsonify([product.to_dict() for product in products])

# Get products by brand
@app.route("/products/brand/<int:brand_id>", methods=["GET"])
def get_products_by_brand(brand_id):
    products = Product.query.filter_by(brand_id=brand_id).all()
    return jsonify([product.to_dict() for product in products])

# Get products sorted by rating
@app.route("/products/rating", methods=["GET"])
def get_products_by_rating():
    products = (
        db.session.query(Product)
        .join(Review)
        .group_by(Product.id)
        .order_by(db.func.avg(Review.rating).desc())
        .all()
    )
    return jsonify([product.to_dict() for product in products])

# Get products sorted by price (ascending or descending)
@app.route("/products/price", methods=["GET"])
def get_products_by_price():
    order = request.args.get("order", "asc")  # Default to ascending
    if order == "desc":
        products = Product.query.order_by(Product.price.desc()).all()
    else:
        products = Product.query.order_by(Product.price.asc()).all()
    
    return jsonify([product.to_dict() for product in products])

@app.route('/reviews/<int:product_id>', methods=['POST'])
@role_required("user_or_admin")
def create_review(product_id):
    print(str(get_jwt_identity()))
    current_user = int(get_jwt_identity())
    print(f"JWT Identity: {current_user} (Type: {type(current_user)})")

    data = request.get_json()

    if 'rating' not in data or 'comment' not in data:
        return jsonify({'error': 'Rating and comment are required'}), 400

    user = User.query.get(int(current_user))
    if not user:
        return jsonify({'error': 'User not found'}), 404

    existing_review = Review.query.filter_by(product_id=product_id, user_id=user.id).first()
    if existing_review:
        return jsonify({'error': 'You have already left a review for this product'}), 400

    new_review = Review(
        name=user.name,
        email=user.email,
        rating=data['rating'],
        comment=data['comment'],
        product_id=product_id,
        user_id=user.id
    )

    db.session.add(new_review)
    db.session.commit()

    return jsonify({'message': 'Review added successfully', 'review': new_review.to_dict()}), 201

@app.route('/reviews/<int:review_id>', methods=['DELETE'])
@role_required("user_or_admin")
def delete_review(review_id):
    current_user = get_jwt_identity()
    review = Review.query.get_or_404(review_id)

    if review.user_id != int(current_user):  
        user = User.query.get(current_user)
        if not user or user.role != 'admin':  
            return jsonify({'error': 'Permission denied'}), 403  

    db.session.delete(review)
    db.session.commit()

    return jsonify({'message': 'Review deleted successfully'})

@app.route('/reviews/<int:review_id>', methods=['PUT'])
@role_required("user_or_admin")
def update_review(review_id):
    current_user = get_jwt_identity()
    data = request.get_json()

    review = Review.query.get_or_404(review_id)

    # Ensure only the review owner can update
    if review.user_id != int(current_user):
        return jsonify({'error': 'You can only update your own review'}), 403

    review.rating = data.get('rating', review.rating)
    review.comment = data.get('comment', review.comment)
    db.session.commit()

    return jsonify({'message': 'Review updated successfully', 'review': review.to_dict()})


@app.route('/reviews/<int:product_id>', methods=['GET'])
def get_reviews(product_id):
    current_user = get_jwt_identity()
    
    # Retrieve only active reviews
    reviews = Review.query.filter_by(product_id=product_id, is_active=True).all()

    # Sort reviews: If user left a review, show it first
    if current_user:
        user_review = next((r for r in reviews if r.user_id == int(current_user['id'])), None)
        if user_review:
            reviews.remove(user_review)
            reviews.insert(0, user_review)

    return jsonify([r.to_dict() for r in reviews])

# @app.route('/request-otp', methods=['POST'])
# def request_otp():
#     data = request.get_json()
#     otp = random.randint(100000, 999999)
#     session['otp'] = otp
#     session['otp_email'] = data['email']
#     send_email(data['email'], 'templates/otp_email.html', {'otp': otp})
#     return jsonify({'message': 'OTP sent to email'})

@app.route('/pay', methods=['POST'])
@role_required("user_or_admin")
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


# def send_email(recipient, template_path, context):
#     with open(template_path) as f:
#         template = f.read()
#     body = template.format(**context)
#     msg = Message('Payment Confirmation', sender=app.config['MAIL_USERNAME'], recipients=[recipient])
#     msg.html = body
#     mail.send(msg)
def send_email(to_email, template_path, context):
    with open(template_path, "r", encoding="utf-8") as file:
        template = Template(file.read())
    body = template.render(context)
    msg = Message('Payment Confirmation', sender=app.config['MAIL_USERNAME'], recipients=[to_email])
    msg.html = body
    mail.send(msg)
    print(f"Sending email to {to_email} with body:\n{body}")

@app.route('/request-otp', methods=['POST'])
def request_otp():
    data = request.get_json()
    email = data.get('email')
    current_time = datetime.datetime.utcnow()

    otp_key = f"otp_{email}_timestamp"
    current_time = datetime.datetime.now(timezone.utc).timestamp()

    if otp_key in session and (current_time - session[otp_key]) < OTP_REQUEST_LIMIT:
        return jsonify({'message': 'Please wait before requesting another OTP'}), 429

    otp = random.randint(100000, 999999)
    session[f"otp_{email}"] = {
    "otp": otp,
    "expires_at": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=OTP_EXPIRY_TIME)
    }    
    session[otp_key] = current_time
    session.permanent = True

    send_email(email, 'templates/otp_email.html', {'otp': otp})
    return jsonify({'message': 'OTP sent to email'})

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')

    if not email or not otp:
        return jsonify({'message': 'Email and OTP are required'}), 400

    success, message = verify_otp_fn(email, otp)

    if success:
        return jsonify({'message': 'OTP verified successfully'}), 200
    else:
        return jsonify({'message': message}), 400
    
@app.route('/cart', methods=['POST'])
@role_required("user_or_admin")
def add_to_cart():
    current_user = int(get_jwt_identity())
    data = request.get_json()

    product_list = data.get('products', [])  # Expecting a list of products with their quantities

    if not product_list:
        return jsonify({"error": "No products provided"}), 400

    db.session.expire_all()

    # Get or create the cart for the user
    cart = Cart.query.filter_by(user_id=current_user, is_delivered=False).first()
    if not cart:
        cart = Cart(user_id=current_user)
        db.session.add(cart)
        db.session.commit()

    for item in product_list:
        try:
            product_id = int(item.get('product_id'))
            quantity = int(item.get('quantity', 1))
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid product ID or quantity"}), 400

        product = Product.query.filter_by(id=product_id).first()
        if not product:
            return jsonify({"error": f"Product {product_id} not found"}), 404

        # Check if requested quantity exceeds inventory
        if quantity > product.inventory:
            return jsonify({
                "error": f"Not enough stock for product {product.name}. Available: {product.inventory}, Requested: {quantity}"
            }), 400

        cart_item = CartItem.query.filter_by(cart_id=cart.id, product_id=product_id).first()
        if cart_item:
            new_quantity = cart_item.quantity + quantity
            if new_quantity > product.inventory:
                return jsonify({
                    "error": f"Not enough stock for product {product.name}. Available: {product.inventory}, Requested: {new_quantity}"
                }), 400
            cart_item.quantity = new_quantity  # Update quantity if within limit
        else:
            cart_item = CartItem(cart_id=cart.id, product_id=product_id, quantity=quantity)
            db.session.add(cart_item)

    db.session.commit()
    return jsonify({"message": "Cart updated", "cart": cart.to_dict()}), 201
    
@app.route('/cart/<int:cart_id>', methods=['GET'])
@role_required("user_or_admin")
def get_cart_by_id(cart_id):
    current_user_id = int(get_jwt_identity())  # Extracts only user_id
    current_user = User.query.get(current_user_id)  # Fetch user from DB

    if not current_user:
        return jsonify({"error": "User not found"}), 404

    cart_item = Cart.query.get_or_404(cart_id)

    if cart_item.user_id != current_user_id and current_user.role != "admin":
        return jsonify({"error": "Forbidden: You are not the owner of this cart"}), 403

    return jsonify({"cart_item": cart_item.to_dict()})


@app.route('/cart', methods=['GET'])
@role_required("admin")
def get_all_carts():
    carts = Cart.query.all()
    return jsonify({"carts": [cart.to_dict() for cart in carts]})

@app.route('/cart/<int:cart_id>', methods=['PUT'])
@role_required("user_or_admin")
def update_cart(cart_id):
    current_user = int(get_jwt_identity())
    data = request.get_json()

    cart = Cart.query.get_or_404(cart_id)

    if cart.user_id != current_user and get_jwt_identity().role != "admin":
        return jsonify({"error": "Forbidden: You are not the owner of this cart"}), 403

    for item in data.get('items', []):
        try:
            product_id = int(item.get('product_id'))
            quantity = int(item.get('quantity'))
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid product ID or quantity"}), 400

        cart_item = CartItem.query.filter_by(cart_id=cart.id, product_id=product_id).first()
        if cart_item:
            if quantity > 0:
                cart_item.quantity = quantity  # Update quantity
            else:
                db.session.delete(cart_item)  # Remove item if quantity is 0

    db.session.commit()
    return jsonify({"message": "Cart updated", "cart": cart.to_dict()})


@app.route('/cart/<int:cart_id>', methods=['DELETE'])
@role_required("admin")
def delete_cart(cart_id):
    cart = Cart.query.get_or_404(cart_id)
    db.session.delete(cart)
    db.session.commit()
    return jsonify({"message": "Cart deleted"})


@app.route('/cart/<int:user_id>', methods=['GET'])
@role_required("user_or_admin")  
def get_cart_by_user(user_id):
    current_user = int(get_jwt_identity())  

    if current_user != user_id:
        user = User.query.get(current_user)
        if not user or user.role != 'admin':  
            return jsonify({'error': 'Permission denied'}), 403  

    carts = Cart.query.filter_by(user_id=user_id).all()
    
    return jsonify({"cart": [cart.to_dict() for cart in carts]})

if __name__ == '__main__':
    app.run(debug=True)
