import json
import pytest
from app import app
from config import client, db
import mongomock
import uuid

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

def test_get_profile(test_client):
    """Test user profile retrieval"""
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
    
    # Login to get token
    login_data = {
        'username': unique_username,
        'password': 'testpassword123'
    }
    login_response = test_client.post('/login', 
                                      data=json.dumps(login_data),
                                      content_type='application/json')
    
    # Verify login
    assert login_response.status_code == 200
    login_result = json.loads(login_response.data)
    assert 'access_token' in login_result
    
    # Get profile with token
    profile_response = test_client.get('/profile', 
                                       headers={
                                           'Authorization': f"Bearer {login_result['access_token']}",
                                           'Content-Type': 'application/json'
                                       })
    
    # Check profile response
    assert profile_response.status_code == 200
    profile_data = json.loads(profile_response.data)
    
    # Verify profile data
    assert 'username' in profile_data
    assert profile_data['username'] == unique_username
    assert 'email' in profile_data
    assert profile_data['email'] == unique_email

def test_update_profile(test_client):
    """Test updating user profile"""
    # First, register and login to get a token
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
    
    # Login to get token
    login_data = {
        'username': unique_username,
        'password': 'testpassword123'
    }
    login_response = test_client.post('/login', 
                                      data=json.dumps(login_data),
                                      content_type='application/json')
    
    # Verify login
    assert login_response.status_code == 200
    login_result = json.loads(login_response.data)
    assert 'access_token' in login_result
    
    # Update profile
    update_data = {
        'first_name': 'Updated',
        'last_name': 'Name'
    }
    
    response = test_client.put('/profile', 
        data=json.dumps(update_data),
        content_type='application/json',
        headers={'Authorization': f'Bearer {login_result["access_token"]}'}
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    
    # Verify updated fields
    assert data['first_name'] == 'Updated'
    assert data['last_name'] == 'Name'

def test_change_password(test_client):
    """Test changing user password"""
    # First, register and login to get a token
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
    
    # Login to get token
    login_data = {
        'username': unique_username,
        'password': 'testpassword123'
    }
    login_response = test_client.post('/login', 
                                      data=json.dumps(login_data),
                                      content_type='application/json')
    
    # Verify login
    assert login_response.status_code == 200
    login_result = json.loads(login_response.data)
    assert 'access_token' in login_result
    
    # Change password
    change_password_data = {
        'current_password': 'testpassword123',
        'new_password': 'newpassword456'
    }
    
    response = test_client.post('/change-password', 
        data=json.dumps(change_password_data),
        content_type='application/json',
        headers={'Authorization': f'Bearer {login_result["access_token"]}'}
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['message'] == 'Password changed successfully'

def test_change_password_invalid(test_client):
    """Test invalid password change scenarios"""
    # First, register and login to get a token
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
    
    # Login to get token
    login_data = {
        'username': unique_username,
        'password': 'testpassword123'
    }
    login_response = test_client.post('/login', 
                                      data=json.dumps(login_data),
                                      content_type='application/json')
    
    # Verify login
    assert login_response.status_code == 200
    login_result = json.loads(login_response.data)
    assert 'access_token' in login_result
    
    # Wrong current password
    wrong_current_pass = {
        'current_password': 'wrongpassword',
        'new_password': 'newpassword456'
    }
    
    response = test_client.post('/change-password', 
        data=json.dumps(wrong_current_pass),
        content_type='application/json',
        headers={'Authorization': f'Bearer {login_result["access_token"]}'}
    )
    
    assert response.status_code == 400

    # Short new password
    short_new_pass = {
        'current_password': 'testpassword123',
        'new_password': '123'
    }
    
    response = test_client.post('/change-password', 
        data=json.dumps(short_new_pass),
        content_type='application/json',
        headers={'Authorization': f'Bearer {login_result["access_token"]}'}
    )
    
    assert response.status_code == 400

def test_unauthorized_access(test_client):
    """Test accessing protected routes without authentication"""
    # Get profile without token
    response = test_client.get('/profile')
    assert response.status_code == 401

    # Update profile without token
    response = test_client.put('/profile', 
        data=json.dumps({'first_name': 'Test'}),
        content_type='application/json'
    )
    assert response.status_code == 401

    # Change password without token
    response = test_client.post('/change-password', 
        data=json.dumps({
            'current_password': 'oldpass',
            'new_password': 'newpass'
        }),
        content_type='application/json'
    )
    assert response.status_code == 401 