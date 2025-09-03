import os
import pytest
import sys
import json
import uuid

# Add the project root directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app
import mongomock
from config import client, db

@pytest.fixture(scope='function')
def test_client():
    """Create a test client using Flask's test_config"""
    app.config['TESTING'] = True
    
    # Mock MongoDB connection
    mock_client = mongomock.MongoClient()
    mock_db = mock_client.db
    
    # Replace the actual MongoDB client with mock client in the app
    client.admin = mock_client.admin
    db.users = mock_db.users
    
    # Clear existing users before each test
    db.users.delete_many({})
    
    with app.test_client() as test_flask_client:
        yield test_flask_client

@pytest.fixture(scope='function')
def jwt_token(test_client):
    """Generate a JWT token for authenticated tests"""
    # Generate unique username and email
    unique_username = f"testuser_{uuid.uuid4().hex[:8]}"
    unique_email = f"{unique_username}@example.com"
    
    # Create a test user
    test_user = {
        'username': unique_username,
        'email': unique_email,
        'password': 'testpassword123'
    }
    
    # Register the user
    register_response = test_client.post('/register', 
        data=json.dumps(test_user),
        content_type='application/json'
    )
    
    # Verify registration
    assert register_response.status_code == 201
    
    # Login to get the token
    login_response = test_client.post('/login', 
        data=json.dumps({
            'username': unique_username,
            'password': 'testpassword123'
        }),
        content_type='application/json'
    )
    
    # Verify login
    assert login_response.status_code == 200
    
    # Return the token
    login_data = json.loads(login_response.data)
    return login_data.get('access_token')

@pytest.fixture
def cleanup_test_data():
    """Cleanup test data after tests"""
    yield
    # Remove test user from database
    db.users.delete_many({
        'username': 'testuser',
        'email': 'test@example.com'
    }) 