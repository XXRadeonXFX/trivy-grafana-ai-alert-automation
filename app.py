# app.py
from flask import Flask, request, jsonify, send_from_directory
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt
from flask_swagger_ui import get_swaggerui_blueprint
from models import User
from config import mongo, client, db
import os
import logging
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load the Flask
app = Flask(__name__)

# Swagger Configuration
SWAGGER_URL = '/swagger'  # URL for exposing Swagger UI (without trailing '/')
API_URL = '/static/swagger.json'  # Our API url (can of course be a local resource)

# Call factory function to create our blueprint
swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,  # Swagger UI static files will be mapped to '{SWAGGER_URL}/dist/'
    API_URL,
    config={  # Swagger UI config overrides
        'app_name': "User Management API"
    }
)
# Register blueprint at URL
app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

# Serve Swagger JSON
@app.route('/static/swagger.json')
def serve_swagger():
    return send_from_directory('static', 'swagger.json')

# JWT Configuration
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'fallback-secret-key')
jwt = JWTManager(app)
bcrypt = Bcrypt(app)

def check_db_connection():
    """
    Check MongoDB connection during app initialization
    """
    try:
        # Attempt to ping the database
        client.admin.command('ping')
        logger.info("Successfully connected to MongoDB")
    except (ConnectionFailure, ServerSelectionTimeoutError) as e:
        logger.error(f"Failed to connect to MongoDB: {e}")
        raise

# Call connection check during app initialization
check_db_connection()

# Home Route
@app.route('/')
def home():
    return jsonify({"message": "Welcome to the Home Page"}), 200

# User Registration
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        
        # Log incoming registration request
        logger.info(f"Registration attempt for username: {data.get('username')}")
        
        # Validate input
        if not data or not data.get('username') or not data.get('email') or not data.get('password'):
            logger.warning("Missing required fields in registration")
            return jsonify({"error": "Missing required fields"}), 400
        
        # Create user
        try:
            user_id = User.create_user(
                db, 
                username=data['username'], 
                email=data['email'], 
                password=data['password'],
                first_name=data.get('first_name'),
                last_name=data.get('last_name')
            )
            
            logger.info(f"User registered successfully: {user_id}")
            return jsonify({
                "message": "User registered successfully", 
                "user_id": str(user_id)
            }), 201
        
        except ValueError as ve:
            logger.warning(f"Validation error during registration: {ve}")
            return jsonify({"error": str(ve)}), 400
        except Exception as create_err:
            logger.error(f"Error creating user: {create_err}", exc_info=True)
            return jsonify({
                "error": "Registration failed", 
                "details": str(create_err)
            }), 500
    
    except Exception as e:
        # Catch any unexpected errors
        logger.error(f"Unexpected error in registration: {e}", exc_info=True)
        return jsonify({
            "error": "Registration failed", 
            "details": str(e)
        }), 500

# User Login
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        # Validate input
        if not data or not data.get('username') or not data.get('password'):
            return jsonify({"error": "Missing username or password"}), 400
        
        # Authenticate user
        user = User.authenticate(db, data['username'], data['password'])
        
        if user:
            # Create access token
            access_token = create_access_token(identity=str(user['_id']))
            return jsonify(access_token=access_token), 200
        
        return jsonify({"error": "Invalid credentials"}), 401
    
    except Exception as e:
        return jsonify({"error": "Login failed"}), 500

# Get User Profile
@app.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    try:
        current_user_id = get_jwt_identity()
        
        # Ensure current_user_id is converted to ObjectId if it's a string
        if isinstance(current_user_id, str):
            from bson import ObjectId
            current_user_id = ObjectId(current_user_id)
        
        # Retrieve user with specific error handling
        user = db.users.find_one({'_id': current_user_id})
        
        if not user:
            # Specific error for user not found
            logger.warning(f"Profile retrieval failed: User not found for ID {current_user_id}")
            return jsonify({"error": "User not found"}), 404
        
        # Remove sensitive information
        user.pop('password_hash', None)
        
        # Convert ObjectId to string for JSON serialization
        user['_id'] = str(user['_id'])
        
        return jsonify(user), 200
    
    except Exception as e:
        # Log the full error for debugging
        logger.error(f"Profile retrieval error: {str(e)}", exc_info=True)
        return jsonify({
            "error": "Failed to retrieve profile", 
            "details": str(e)
        }), 500

# Edit User Profile
@app.route('/profile', methods=['PUT'])
@jwt_required()
def edit_profile():
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()
        
        # Validate input
        if not data or (not data.get('first_name') and not data.get('last_name')):
            return jsonify({"error": "No profile data provided"}), 400
        
        # Update user profile
        success = User.update_user(db, current_user_id, {
            'first_name': data.get('first_name'),
            'last_name': data.get('last_name')
        })
        
        if not success:
            return jsonify({"error": "Failed to update profile"}), 400
        
        # Retrieve updated user
        updated_user = User.get_user_by_id(db, current_user_id)
        return jsonify(updated_user), 200
    
    except Exception as e:
        logger.error(f"Profile update error: {str(e)}", exc_info=True)
        return jsonify({"error": "Profile update failed"}), 500

# Change Password
@app.route('/change-password', methods=['POST'])
@jwt_required()
def change_password():
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()
        
        # Validate input
        if not data.get('current_password') or not data.get('new_password'):
            return jsonify({"error": "Missing current or new password"}), 400
        
        # Validate new password length
        if len(data['new_password']) < 6:
            return jsonify({"error": "New password must be at least 6 characters long"}), 400
        
        # Change password
        success = User.change_password(
            db, 
            current_user_id, 
            data['current_password'], 
            data['new_password']
        )
        
        if not success:
            return jsonify({"error": "Password change failed"}), 400
        
        return jsonify({"message": "Password changed successfully"}), 200
    
    except Exception as e:
        logger.error(f"Password change error: {str(e)}", exc_info=True)
        return jsonify({"error": "Password change failed"}), 500

# Logout (handled client-side by removing token)
@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    # In JWT, logout is typically handled client-side by removing the token
    return jsonify({"message": "Logged out successfully"}), 200

# # Register the product blueprint
# app.register_blueprint(product_bp)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)

