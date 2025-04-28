import os
import sys
from datetime import datetime, timedelta
from app import app, db
from models import User, PacketLog, NetworkStats, Config, Alert

def migrate_database():
    """
    Migrate the database to add user relationships to existing data.
    """
    with app.app_context():
        try:
            # Get the first user (or create a default one if none exists)
            default_user = User.query.first()
            if not default_user:
                print("No users found. Creating a default user.")
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
                print(f"Created default user with ID: {default_user.id}")
            
            # Update PacketLog records
            packet_count = 0
            for packet in PacketLog.query.filter_by(user_id=None).all():
                packet.user_id = default_user.id
                packet_count += 1
                if packet_count % 100 == 0:
                    db.session.commit()
                    print(f"Updated {packet_count} packet logs...")
            
            # Update NetworkStats records
            stats_count = 0
            for stat in NetworkStats.query.filter_by(user_id=None).all():
                stat.user_id = default_user.id
                stats_count += 1
                if stats_count % 100 == 0:
                    db.session.commit()
                    print(f"Updated {stats_count} network stats...")
            
            # Update Config records
            config_count = 0
            for config in Config.query.filter_by(user_id=None).all():
                config.user_id = default_user.id
                config_count += 1
            
            # Final commit
            db.session.commit()
            print(f"Migration complete. Updated {packet_count} packet logs, {stats_count} network stats, and {config_count} configs.")
            
        except Exception as e:
            db.session.rollback()
            print(f"Error during migration: {str(e)}")
            raise

if __name__ == "__main__":
    migrate_database()