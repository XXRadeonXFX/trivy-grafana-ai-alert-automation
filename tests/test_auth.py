import json
import pytest
import uuid
from app import app
from config import client, db
import mongomock

@pytest.fixture
def test_client():
    """Create a test client using Flask's test_config"""
    app.config['TESTING'] = True
    
    # Mock MongoDB connection
    mock_client = mongomock.MongoClient()
    mock_db = mock_client.db
    
    # Replace the actual MongoDB client with mock client in the app
    from config import client as mongo_client, db as mongo_db
    mongo_client.admin = mock_client.admin
    mongo_db.users = mock_db.users
    
    # Clear existing users before each test
    mongo_db.users.delete_many({})
    
    with app.test_client() as test_flask_client:
        yield test_flask_client

def test_register_success(test_client):
    """Test successful user registration"""
    # Generate unique username and email
    unique_username = f"testuser_{uuid.uuid4().hex[:8]}"
    unique_email = f"{unique_username}@example.com"
    
    # Prepare test user data
    user_data = {
        'username': unique_username,
        'email': unique_email,
        'password': 'testpassword123'
    }
    
    # Register user
    register_response = test_client.post('/register', 
                                         data=json.dumps(user_data),
                                         content_type='application/json')
    
    # Verify registration
    assert register_response.status_code == 201
    register_data = json.loads(register_response.data)
    assert 'user_id' in register_data

def test_register_invalid_email(test_client):
    """Test registration with invalid email"""
    user_data = {
        'username': 'testuser',
        'email': 'invalid-email',
        'password': 'testpassword123'
    }
    
    register_response = test_client.post('/register', 
                                         data=json.dumps(user_data),
                                         content_type='application/json')
    
    assert register_response.status_code == 400
    error_data = json.loads(register_response.data)
    assert 'error' in error_data
    assert 'Invalid email format' in error_data['error']

def test_register_existing_username(test_client):
    """Test registration with existing username"""
    # First registration
    user_data1 = {
        'username': 'existinguser',
        'email': 'first@example.com',
        'password': 'testpassword123'
    }
    
    register_response1 = test_client.post('/register', 
                                          data=json.dumps(user_data1),
                                          content_type='application/json')
    assert register_response1.status_code == 201
    
    # Second registration with same username
    user_data2 = {
        'username': 'existinguser',
        'email': 'second@example.com',
        'password': 'testpassword456'
    }
    
    register_response2 = test_client.post('/register', 
                                          data=json.dumps(user_data2),
                                          content_type='application/json')
    
    assert register_response2.status_code == 400
    error_data = json.loads(register_response2.data)
    assert 'error' in error_data
    assert 'Username or email already exists' in error_data['error']

def test_register_short_username(test_client):
    """Test registration with short username"""
    user_data = {
        'username': 'us',  # Too short
        'email': 'test@example.com',
        'password': 'testpassword123'
    }
    
    register_response = test_client.post('/register', 
                                         data=json.dumps(user_data),
                                         content_type='application/json')
    
    assert register_response.status_code == 400
    error_data = json.loads(register_response.data)
    assert 'error' in error_data
    assert 'Username must be at least 3 characters long' in error_data['error']

def test_register_short_password(test_client):
    """Test registration with short password"""
    user_data = {
        'username': 'testuser',
        'email': 'test@example.com',
        'password': '123'  # Too short
    }
    
    register_response = test_client.post('/register', 
                                         data=json.dumps(user_data),
                                         content_type='application/json')
    
    assert register_response.status_code == 400
    error_data = json.loads(register_response.data)
    assert 'error' in error_data
    assert 'Password must be at least 6 characters long' in error_data['error']

def test_login_success(test_client):
    """Test successful login"""
    # First, register a user
    unique_username = f"testuser_{uuid.uuid4().hex[:8]}"
    unique_email = f"{unique_username}@example.com"
    
    user_data = {
        'username': unique_username,
        'email': unique_email,
        'password': 'testpassword123'
    }
    
    register_response = test_client.post('/register', 
                                         data=json.dumps(user_data),
                                         content_type='application/json')
    assert register_response.status_code == 201
    
    # Now login
    login_data = {
        'username': unique_username,
        'password': 'testpassword123'
    }
    
    login_response = test_client.post('/login', 
                                      data=json.dumps(login_data),
                                      content_type='application/json')
    
    assert login_response.status_code == 200
    login_result = json.loads(login_response.data)
    assert 'access_token' in login_result

def test_login_incorrect_credentials(test_client):
    """Test login with incorrect credentials"""
    # First, register a user
    unique_username = f"testuser_{uuid.uuid4().hex[:8]}"
    unique_email = f"{unique_username}@example.com"
    
    user_data = {
        'username': unique_username,
        'email': unique_email,
        'password': 'testpassword123'
    }
    
    register_response = test_client.post('/register', 
                                         data=json.dumps(user_data),
                                         content_type='application/json')
    assert register_response.status_code == 201
    
    # Try login with wrong password
    login_data = {
        'username': unique_username,
        'password': 'wrongpassword'
    }
    
    login_response = test_client.post('/login', 
                                      data=json.dumps(login_data),
                                      content_type='application/json')
    
    assert login_response.status_code == 401
    login_result = json.loads(login_response.data)
    assert 'error' in login_result
    assert login_result['error'] == 'Invalid credentials'

def test_login_missing_credentials(test_client):
    """Test login with missing credentials"""
    # Try login without username
    login_data1 = {
        'password': 'testpassword123'
    }
    
    login_response1 = test_client.post('/login', 
                                       data=json.dumps(login_data1),
                                       content_type='application/json')
    
    assert login_response1.status_code == 400
    
    # Try login without password
    login_data2 = {
        'username': 'testuser'
    }
    
    login_response2 = test_client.post('/login', 
                                       data=json.dumps(login_data2),
                                       content_type='application/json')
    
    assert login_response2.status_code == 400 