from database import db, SystemLog

def log_system(user_id, log_type, message, request=None):
    """Create system log entry."""
    try:
        ip = request.remote_addr if request else None
        ua = request.user_agent.string if request and request.user_agent else None
        log = SystemLog(
            user_id=user_id,
            log_type=log_type,
            message=message[:500],
            ip_address=ip,
            user_agent=ua[:500] if ua else None
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Failed to create system log: {e}")