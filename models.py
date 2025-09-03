from flask_bcrypt import Bcrypt
from datetime import datetime
from bson.objectid import ObjectId
import re

bcrypt = Bcrypt()

class User:
    """
    User model for MongoDB
    """
    @staticmethod
    def validate_email(email):
        """
        Validate email format
        """
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(email_regex, email) is not None

    @staticmethod
    def create_user(mongo_db, username, email, password, first_name=None, last_name=None):
        """
        Create a new user in the database
        """
        # Validate inputs
        if not username or len(username) < 3:
            raise ValueError("Username must be at least 3 characters long")
        
        if not User.validate_email(email):
            raise ValueError("Invalid email format")
        
        if not password or len(password) < 6:
            raise ValueError("Password must be at least 6 characters long")

        # Check if username or email already exists
        existing_user = mongo_db.users.find_one({
            '$or': [
                {'username': username},
                {'email': email}
            ]
        })
        
        if existing_user:
            raise ValueError("Username or email already exists")

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Prepare user document
        user_doc = {
            'username': username,
            'email': email,
            'password_hash': hashed_password,
            'first_name': first_name,
            'last_name': last_name,
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }

        # Insert user and return the inserted ID
        result = mongo_db.users.insert_one(user_doc)
        return result.inserted_id

    @staticmethod
    def authenticate(mongo_db, username, password):
        """
        Authenticate user
        """
        user = mongo_db.users.find_one({'username': username})
        
        if user and bcrypt.check_password_hash(user['password_hash'], password):
            return user
        
        return None

    @staticmethod
    def get_user_by_id(mongo_db, user_id):
        """
        Get user by MongoDB ObjectId
        """
        try:
            # Convert string to ObjectId if needed
            if isinstance(user_id, str):
                user_id = ObjectId(user_id)
            
            user = mongo_db.users.find_one({'_id': user_id})
            
            if user:
                # Remove sensitive information and convert _id to string
                user.pop('password_hash', None)
                user['_id'] = str(user['_id'])
                return user
            
            return None
        except Exception:
            return None

    @staticmethod
    def update_user(mongo_db, user_id, update_data):
        """
        Update user profile
        """
        try:
            # Convert string to ObjectId if needed
            if isinstance(user_id, str):
                user_id = ObjectId(user_id)
            
            # Prepare update document
            update_doc = {
                '$set': {
                    'first_name': update_data.get('first_name'),
                    'last_name': update_data.get('last_name'),
                    'updated_at': datetime.utcnow()
                }
            }
            
            # Remove None values
            update_doc['$set'] = {k: v for k, v in update_doc['$set'].items() if v is not None}
            
            # Update user
            result = mongo_db.users.update_one({'_id': user_id}, update_doc)
            
            return result.modified_count > 0
        except Exception:
            return False

    @staticmethod
    def change_password(mongo_db, user_id, current_password, new_password):
        """
        Change user password
        """
        try:
            # Convert string to ObjectId if needed
            if isinstance(user_id, str):
                user_id = ObjectId(user_id)
            
            # Find user
            user = mongo_db.users.find_one({'_id': user_id})
            
            # Verify current password
            if not user or not bcrypt.check_password_hash(user['password_hash'], current_password):
                return False
            
            # Hash new password
            new_password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
            
            # Update password
            result = mongo_db.users.update_one(
                {'_id': user_id}, 
                {'$set': {
                    'password_hash': new_password_hash,
                    'updated_at': datetime.utcnow()
                }}
            )
            
            return result.modified_count > 0
        except Exception:
            return False 