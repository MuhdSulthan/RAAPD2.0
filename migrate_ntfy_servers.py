import os
import logging
import sqlalchemy as sa
from sqlalchemy.exc import OperationalError
from sqlalchemy import create_engine, text

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def execute_sql(sql, params=None):
    """Execute SQL directly with SQLAlchemy engine"""
    engine = create_engine(os.environ.get("DATABASE_URL"))
    with engine.connect() as connection:
        if params:
            connection.execute(text(sql), params)
        else:
            connection.execute(text(sql))
        connection.commit()

def check_column_exists(table, column):
    """Check if column exists in table"""
    engine = create_engine(os.environ.get("DATABASE_URL"))
    sql = f"""
    SELECT column_name 
    FROM information_schema.columns 
    WHERE table_name = '{table}' AND column_name = '{column}'
    """
    with engine.connect() as connection:
        result = connection.execute(text(sql))
        exists = result.fetchone() is not None
    
    return exists

def migrate():
    """Run database migrations for ntfy.sh multi-server support"""
    try:
        # Check if the column already exists
        if not check_column_exists('user', 'ntfy_servers'):
            # Add the new column for ntfy servers
            logger.info("Adding ntfy_servers column to user table")
            execute_sql("""
            ALTER TABLE "user" ADD COLUMN IF NOT EXISTS ntfy_servers TEXT DEFAULT '[]'
            """)
            logger.info("ntfy_servers column added successfully")
        else:
            logger.info("ntfy_servers column already exists in user table")
        
        return True
    except Exception as e:
        logger.error(f"Migration error: {str(e)}")
        return False

if __name__ == "__main__":
    migrate()