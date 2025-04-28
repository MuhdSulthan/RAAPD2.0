import os
import sys
import logging
from datetime import datetime
from app import app, db
from models import User

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def execute_sql(sql, params=None):
    """Execute SQL directly with SQLAlchemy engine"""
    with app.app_context():
        conn = db.engine.connect()
        try:
            trans = conn.begin()
            if params:
                conn.execute(sql, params)
            else:
                conn.execute(sql)
            trans.commit()
            logger.info(f"Successfully executed SQL: {sql[:60]}...")
            return True
        except Exception as e:
            trans.rollback()
            logger.error(f"Error executing SQL '{sql[:60]}...': {str(e)}")
            return False
        finally:
            conn.close()

def check_column_exists(table, column):
    """Check if column exists in table"""
    with app.app_context():
        sql = f"""
        SELECT EXISTS (
            SELECT 1 
            FROM information_schema.columns 
            WHERE table_name='{table}' AND column_name='{column}'
        );
        """
        result = db.session.execute(sql).scalar()
        return result

def get_default_user_id():
    """Get or create a default user to associate with existing records"""
    with app.app_context():
        default_user = User.query.first()
        if not default_user:
            logger.info("No users found. Creating a default user.")
            from werkzeug.security import generate_password_hash
            default_user = User(
                username="admin",
                email="admin@example.com",
                password_hash=generate_password_hash("securepassword"),
                is_active=True,
                is_admin=True,
                created_at=datetime.utcnow()
            )
            db.session.add(default_user)
            db.session.commit()
            logger.info(f"Created default user with ID: {default_user.id}")
        return default_user.id

def migrate():
    """Run all database migrations"""
    try:
        default_user_id = get_default_user_id()
        
        # Add user_id column to packet_log if it doesn't exist
        if not check_column_exists('packet_log', 'user_id'):
            logger.info("Adding user_id column to packet_log table...")
            execute_sql("ALTER TABLE packet_log ADD COLUMN user_id INTEGER REFERENCES user(id);")
            
            # Set default user for all existing records
            execute_sql("UPDATE packet_log SET user_id = :user_id WHERE user_id IS NULL;", 
                       {"user_id": default_user_id})
            
            logger.info("packet_log migration completed successfully")
        else:
            logger.info("packet_log table already has user_id column")
        
        # Add user_id column to network_stats if it doesn't exist
        if not check_column_exists('network_stats', 'user_id'):
            logger.info("Adding user_id column to network_stats table...")
            execute_sql("ALTER TABLE network_stats ADD COLUMN user_id INTEGER REFERENCES user(id);")
            
            # Set default user for all existing records
            execute_sql("UPDATE network_stats SET user_id = :user_id WHERE user_id IS NULL;",
                       {"user_id": default_user_id})
            
            logger.info("network_stats migration completed successfully")
        else:
            logger.info("network_stats table already has user_id column")
        
        # Add user_id column to config if it doesn't exist
        if not check_column_exists('config', 'user_id'):
            logger.info("Adding user_id column to config table...")
            execute_sql("ALTER TABLE config ADD COLUMN user_id INTEGER REFERENCES user(id);")
            
            # Set default user for all existing records
            execute_sql("UPDATE config SET user_id = :user_id WHERE user_id IS NULL;",
                       {"user_id": default_user_id})
            
            logger.info("config migration completed successfully")
        else:
            logger.info("config table already has user_id column")
        
        logger.info("All migrations completed successfully")
        return True
    except Exception as e:
        logger.error(f"Migration failed: {str(e)}")
        return False

if __name__ == "__main__":
    migrate()