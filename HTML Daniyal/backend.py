from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

app = Flask(_name_)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///food_donation.db'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)

# User Model (Common for both Donors and Organizations)
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # "donor" or "organization"

# Donation Model
class Donation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    donor_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    organization_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    item_name = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.String(50), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), default="Pending")  # "Pending" or "Accepted"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Route: User Registration
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(email=data['email'], password=hashed_password, role=data['role'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered successfully!"})

# Route: User Login
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        login_user(user)
        return jsonify({"message": "Login successful", "role": user.role})
    return jsonify({"message": "Invalid credentials"}), 401

# Route: Donor adds a donation
@app.route('/donate', methods=['POST'])
@login_required
def donate():
    if current_user.role != "donor":
        return jsonify({"message": "Unauthorized"}), 403

    data = request.json
    donation = Donation(
        donor_id=current_user.id,
        organization_id=data['organization_id'],
        item_name=data['item_name'],
        quantity=data['quantity'],
        address=data['address']
    )
    db.session.add(donation)
    db.session.commit()
    return jsonify({"message": "Donation submitted successfully!"})

# Route: Organization views all donation requests
@app.route('/organization/donations', methods=['GET'])
@login_required
def view_donations():
    if current_user.role != "organization":
        return jsonify({"message": "Unauthorized"}), 403

    donations = Donation.query.filter_by(organization_id=current_user.id).all()
    return jsonify([{
        "id": d.id, "item_name": d.item_name, "quantity": d.quantity,
        "address": d.address, "status": d.status
    } for d in donations])

# Route: Organization accepts a donation
@app.route('/organization/accept/<int:donation_id>', methods=['POST'])
@login_required
def accept_donation(donation_id):
    if current_user.role != "organization":
        return jsonify({"message": "Unauthorized"}), 403

    donation = Donation.query.get(donation_id)
    if donation and donation.organization_id == current_user.id:
        donation.status = "Accepted"
        db.session.commit()
        return jsonify({"message": "Donation accepted!"})
    return jsonify({"message": "Donation not found"}), 404

# Route: Donor views donation status
@app.route('/donor/donations', methods=['GET'])
@login_required
def donor_donations():
    if current_user.role != "donor":
        return jsonify({"message": "Unauthorized"}), 403

    donations = Donation.query.filter_by(donor_id=current_user.id).all()
    return jsonify([{
        "item_name": d.item_name, "quantity": d.quantity, "status": d.status
    } for d in donations])

# Route: Logout
@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logged out successfully"})

if _name_ == "_main_":
    with app.app_context():
        db.create_all()  # Creates database tables if they don't exist
    app.run(debug=True)
