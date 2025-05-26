"""
Data Collection System for Real Statistics
Collects and stores operational metrics in database
"""

import datetime
from datetime import timezone
import json
import os
import threading
import time
from flask import current_app
from logging import getLogger
from .models import db, SystemMetric, WalletConnection, OperationMetric, SystemLog, SecurityEvent, Certificate
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError

# Try to import psutil for system metrics
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

logger = getLogger("LOGGER")


class DataCollector:
    """Collects and stores real operational metrics"""
    
    def __init__(self, app=None):
        self.app = app
        self.collection_thread = None
        self.stop_collection = False
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize data collector with Flask app"""
        self.app = app
        app.extensions['data_collector'] = self
        
        # Start background collection thread
        self.start_collection()
    
    def start_collection(self):
        """Start background data collection"""
        if self.collection_thread and self.collection_thread.is_alive():
            return
        
        self.stop_collection = False
        self.collection_thread = threading.Thread(
            target=self._collection_loop,
            daemon=True,
            name="DataCollector"
        )
        self.collection_thread.start()
        logger.info("Data collector started")
    
    def stop(self):
        """Stop data collection"""
        self.stop_collection = True
        if self.collection_thread:
            self.collection_thread.join(timeout=5)
        logger.info("Data collector stopped")
    
    def _collection_loop(self):
        """Main collection loop - runs in background thread"""
        while not self.stop_collection:
            try:
                with self.app.app_context():
                    # Collect system metrics every 30 seconds
                    self.collect_system_metrics()
                    
                    # Clean old metrics (keep last 24 hours)
                    self.cleanup_old_metrics()
                
                # Wait 30 seconds before next collection
                time.sleep(30)
                
            except Exception as e:
                logger.error(f"Error in data collection loop: {e}")
                time.sleep(60)  # Wait longer on error
    
    def collect_system_metrics(self):
        """Collect current system performance metrics"""
        try:
            timestamp = datetime.datetime.now(timezone.utc)
            
            if HAS_PSUTIL:
                # CPU metrics
                cpu_percent = psutil.cpu_percent(interval=0.1)
                self._store_metric(timestamp, 'system', 'cpu_percent', cpu_percent, '%')
                
                # Memory metrics
                memory = psutil.virtual_memory()
                self._store_metric(timestamp, 'system', 'memory_total', memory.total / (1024**3), 'GB')
                self._store_metric(timestamp, 'system', 'memory_used', memory.used / (1024**3), 'GB')
                self._store_metric(timestamp, 'system', 'memory_percent', memory.percent, '%')
                
                # Disk metrics
                disk = psutil.disk_usage('/')
                self._store_metric(timestamp, 'system', 'disk_total', disk.total / (1024**3), 'GB')
                self._store_metric(timestamp, 'system', 'disk_used', disk.used / (1024**3), 'GB')
                self._store_metric(timestamp, 'system', 'disk_percent', (disk.used / disk.total) * 100, '%')
                
                # Network I/O
                net_io = psutil.net_io_counters()
                self._store_metric(timestamp, 'network', 'bytes_sent', net_io.bytes_sent / (1024**2), 'MB')
                self._store_metric(timestamp, 'network', 'bytes_recv', net_io.bytes_recv / (1024**2), 'MB')
                
                # Process count
                process_count = len(psutil.pids())
                self._store_metric(timestamp, 'system', 'process_count', process_count, 'count')
                
                # Load averages (Unix/Linux only)
                try:
                    load_avg = os.getloadavg()
                    self._store_metric(timestamp, 'system', 'load_avg_1m', load_avg[0], 'load')
                    self._store_metric(timestamp, 'system', 'load_avg_5m', load_avg[1], 'load')
                    self._store_metric(timestamp, 'system', 'load_avg_15m', load_avg[2], 'load')
                except (AttributeError, OSError):
                    pass
            
            else:
                # Fallback metrics when psutil not available
                try:
                    disk_info = os.statvfs('/')
                    disk_total = (disk_info.f_frsize * disk_info.f_blocks) / (1024**3)
                    disk_used = (disk_info.f_frsize * (disk_info.f_blocks - disk_info.f_available)) / (1024**3)
                    disk_percent = (disk_used / disk_total) * 100
                    
                    self._store_metric(timestamp, 'system', 'disk_total', disk_total, 'GB')
                    self._store_metric(timestamp, 'system', 'disk_used', disk_used, 'GB')
                    self._store_metric(timestamp, 'system', 'disk_percent', disk_percent, '%')
                except:
                    pass
            
            # Database connection metrics
            try:
                # Count active database connections
                result = db.session.execute(
                    db.text("SELECT count(*) FROM pg_stat_activity WHERE state = 'active'")
                ).scalar()
                if result:
                    self._store_metric(timestamp, 'database', 'active_connections', result, 'count')
            except:
                pass
            
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
    
    def _store_metric(self, timestamp, metric_type, metric_name, value, unit=None):
        """Store a single metric in database"""
        try:
            metric = SystemMetric(
                timestamp=timestamp,
                metric_type=metric_type,
                metric_name=metric_name,
                value=float(value),
                unit=unit
            )
            db.session.add(metric)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error storing metric {metric_name}: {e}")
    
    def cleanup_old_metrics(self):
        """Remove metrics older than 24 hours to prevent database bloat"""
        try:
            cutoff_time = datetime.datetime.now(timezone.utc) - datetime.timedelta(hours=24)
            
            deleted = SystemMetric.query.filter(
                SystemMetric.timestamp < cutoff_time
            ).delete()
            
            if deleted > 0:
                db.session.commit()
                logger.debug(f"Cleaned up {deleted} old metrics")
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error cleaning up old metrics: {e}")


# Event tracking functions for application events
def track_wallet_connection(wallet_id, user_agent=None, ip_address=None):
    """Track a wallet connection event"""
    try:
        connection = WalletConnection(
            wallet_id=wallet_id,
            connected_at=datetime.datetime.now(timezone.utc),
            user_agent=user_agent,
            ip_address=ip_address,
            is_active=True
        )
        db.session.add(connection)
        db.session.commit()
        logger.info(f"Tracked wallet connection: {wallet_id}")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error tracking wallet connection: {e}")


def track_wallet_disconnection(wallet_id):
    """Track a wallet disconnection event"""
    try:
        connection = WalletConnection.query.filter_by(
            wallet_id=wallet_id,
            is_active=True
        ).first()
        
        if connection:
            connection.is_active = False
            connection.disconnected_at = datetime.datetime.now(timezone.utc)
            db.session.commit()
            logger.info(f"Tracked wallet disconnection: {wallet_id}")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error tracking wallet disconnection: {e}")


def track_operation(operation_type, status, duration_ms=None, details=None, user_id=None):
    """Track an operation (issuance, verification, etc.)"""
    try:
        operation = OperationMetric(
            timestamp=datetime.datetime.now(timezone.utc),
            operation_type=operation_type,
            status=status,
            duration_ms=duration_ms,
            user_id=user_id,
            details=details
        )
        db.session.add(operation)
        db.session.commit()
        logger.debug(f"Tracked operation: {operation_type} - {status}")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error tracking operation: {e}")


def track_security_event(event_type, severity, description, source_ip=None, user_id=None, details=None):
    """Track a security event"""
    try:
        event = SecurityEvent(
            timestamp=datetime.datetime.now(timezone.utc),
            event_type=event_type,
            severity=severity,
            description=description,
            source_ip=source_ip,
            user_id=user_id,
            details=details
        )
        db.session.add(event)
        db.session.commit()
        logger.warning(f"Security event: {event_type} - {description}")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error tracking security event: {e}")


def log_to_database(level, source, message, category='system', details=None):
    """Store log entry in database"""
    try:
        log_entry = SystemLog(
            timestamp=datetime.datetime.now(timezone.utc),
            level=level,
            source=source,
            message=message,
            category=category,
            details=details
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error storing log to database: {e}")


# Initialize data collector instance
data_collector = DataCollector()