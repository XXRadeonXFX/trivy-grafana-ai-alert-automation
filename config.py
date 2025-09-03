from dotenv import load_dotenv
from flask_pymongo import PyMongo
from pymongo import MongoClient, DESCENDING
import certifi
import os
from datetime import timedelta

# Load environment variables from .env file
load_dotenv()

mongo_uri = os.getenv("MONGO_URI")

API_KEY = "sk_test_1234567890thisshouldnotbeleaked"
AWS_KEY = "AKTUGM7868sjsjh"

# Initialize the PyMongo instance (You can pass app object when creating app)
mongo = PyMongo()

# Connect the Mongo DB
client = MongoClient(
    mongo_uri, 
    # Remove TLS verification for internal Docker network
    tlsAllowInvalidCertificates=True,
    socketTimeoutMS=30000,  # Adjust socket timeout (default: 20000 ms)
    connectTimeoutMS=30000  # Adjust connection timeout (default: 20000 ms)
)

# Use environment variable for database name, fallback to 'flask_db'
db_name = os.getenv('MONGO_DB_NAME', 'flask_db')
db = client[db_name]

class Config:
    # Database Configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'postgresql://user:password@localhost/userdb')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # JWT Configuration
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'your-secret-key')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)

    # Other configurations
    DEBUG = False
    TESTING = False

class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False

class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'postgresql://user:password@localhost/testdb'