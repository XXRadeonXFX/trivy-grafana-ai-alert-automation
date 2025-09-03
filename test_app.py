import pytest
import json
from app import app
from config import client, db
import mongomock

@pytest.fixture
def client():
    """Create a test client using Flask's test_config"""
    app.config['TESTING'] = True
    
    # Mock MongoDB connection
    mock_client = mongomock.MongoClient()
    mock_db = mock_client.db
    
    # Replace the actual MongoDB client with mock client in the app
    client.admin = mock_client.admin
    db.users = mock_db.users
    
    with app.test_client() as client:
        yield client

def test_home_route(client):
    """Test the home route"""
    response = client.get('/')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'message' in data
    assert data['message'] == "Welcome to the Home Page"

def test_user_registration(client):
    """Test user registration"""
    # Prepare test user data
    user_data = {
        'username': 'testuser',
        'email': 'testuser@example.com',
        'password': 'testpassword123'
    }
    
    # Send registration request
    response = client.post('/register', 
                           data=json.dumps(user_data),
                           content_type='application/json')
    
    # Check response
    assert response.status_code == 201
    data = json.loads(response.data)
    assert 'user_id' in data
    assert 'message' in data
    assert 'User registered successfully' in data['message']

def test_invalid_registration(client):
    """Test registration with missing fields"""
    # Prepare incomplete user data
    user_data = {
        'username': 'testuser'
    }
    
    # Send registration request
    response = client.post('/register', 
                           data=json.dumps(user_data),
                           content_type='application/json')
    
    # Check response
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'error' in data
    assert 'Missing required fields' in data['error']

def test_login_route(client):
    """Test login route"""
    # First, register a user
    user_data = {
        'username': 'loginuser',
        'email': 'loginuser@example.com',
        'password': 'loginpassword123'
    }
    client.post('/register', 
                data=json.dumps(user_data),
                content_type='application/json')
    
    # Now attempt login
    login_data = {
        'username': 'loginuser',
        'password': 'loginpassword123'
    }
    
    response = client.post('/login', 
                           data=json.dumps(login_data),
                           content_type='application/json')
    
    # Check response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'access_token' in data 