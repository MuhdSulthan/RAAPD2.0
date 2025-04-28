import logging
import os
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def execute_sql(sql, params=None):
    """Execute SQL directly with SQLAlchemy engine"""
    from app import db
    
    try:
        if params:
            result = db.session.execute(text(sql), params)
        else:
            result = db.session.execute(text(sql))
        
        db.session.commit()
        return result
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"SQL Error: {str(e)}")
        raise
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error: {str(e)}")
        raise

def check_column_exists(table, column):
    """Check if column exists in table"""
    from app import db
    
    sql = """
    SELECT column_name 
    FROM information_schema.columns 
    WHERE table_name = :table_name AND column_name = :column_name
    """
    
    try:
        result = db.session.execute(text(sql), {
            'table_name': table,
            'column_name': column
        })
        return bool(result.first())
    except Exception as e:
        logger.error(f"Error checking column: {str(e)}")
        return False

def migrate():
    """Run database migrations for lockout notification tracking"""
    logger.info("Starting lockout notification migration...")
    
    # Check if the column already exists
    if check_column_exists('user', 'lockout_notification_sent'):
        logger.info("Column 'lockout_notification_sent' already exists in 'user' table. Skipping migration.")
        return
    
    # Add the column for tracking lockout notification status
    try:
        execute_sql("ALTER TABLE \"user\" ADD COLUMN lockout_notification_sent BOOLEAN DEFAULT FALSE")
        logger.info("Added 'lockout_notification_sent' column to 'user' table.")
    except Exception as e:
        logger.error(f"Failed to add column: {str(e)}")
        return
    
    # Success
    logger.info("Lockout notification migration completed successfully.")

if __name__ == "__main__":
    from app import app
    with app.app_context():
        migrate()