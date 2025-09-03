from config import client, db

def init_database():
    """
    Initialize database collections and create indexes
    """
    # Create users collection with unique indexes
    users_collection = db.users
    
    # Create unique index on username
    users_collection.create_index('username', unique=True)
    
    # Create unique index on email
    users_collection.create_index('email', unique=True)
    
    print("Database initialized successfully!")

if __name__ == '__main__':
    init_database() 