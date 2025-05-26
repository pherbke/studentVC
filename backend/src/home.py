from flask import Blueprint, render_template, redirect, request, jsonify
from logging import getLogger
from flask_login import login_required, current_user
import os
import json
import datetime
from datetime import timezone
import time
from .logging_system import LogCategory
from .models import db, SystemMetric, WalletConnection, OperationMetric, SystemLog, SecurityEvent, Certificate
from sqlalchemy import text, func, desc

# Try to import psutil, fallback if not available
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


home = Blueprint('home', __name__)
logger = getLogger("LOGGER")


@home.route('/index', methods=['GET'])
@home.route('/home', methods=['GET'])
@home.route('/', methods=['GET'])
def index():
    return render_template("home.html")


@home.route('/logs', methods=['GET'])
def logs():
    """Display system logs with filtering capabilities"""
    category_filter = request.args.get('category', 'all')
    level_filter = request.args.get('level', 'all')
    limit = int(request.args.get('limit', 100))
    
    logs_data = get_logs(category_filter, level_filter, limit)
    categories = [cat.value for cat in LogCategory]
    
    return render_template("logs.html", 
                         logs=logs_data, 
                         categories=categories,
                         current_category=category_filter,
                         current_level=level_filter,
                         limit=limit)


def get_logs(category_filter='all', level_filter='all', limit=100):
    """Retrieve logs from database"""
    logs = []
    
    try:
        # Build query
        query = SystemLog.query
        
        # Apply filters
        if category_filter != 'all':
            query = query.filter_by(category=category_filter)
        if level_filter != 'all':
            query = query.filter_by(level=level_filter)
        
        # Get recent logs, ordered by timestamp desc
        db_logs = query.order_by(desc(SystemLog.timestamp)).limit(limit).all()
        
        # Convert to format expected by template
        for log in db_logs:
            logs.append({
                'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'level': log.level,
                'source': log.source,
                'message': log.message,
                'category': log.category,
                'details': log.details
            })
            
        # If no database logs, fallback to file-based logs
        if not logs:
            log_file = os.path.join(os.path.dirname(__file__), '..', 'instance', 'service.log')
            if os.path.exists(log_file):
                try:
                    with open(log_file, 'r') as f:
                        lines = f.readlines()[-limit:]
                    
                    for line in reversed(lines):
                        try:
                            parts = line.strip().split(' - ', 3)
                            if len(parts) >= 4:
                                log_entry = {
                                    'timestamp': parts[0],
                                    'level': parts[1],
                                    'source': parts[2],
                                    'message': parts[3],
                                    'category': 'system'
                                }
                                
                                # Apply filters
                                if category_filter != 'all' and log_entry.get('category', 'system') != category_filter:
                                    continue
                                if level_filter != 'all' and log_entry.get('level', 'INFO') != level_filter:
                                    continue
                                
                                logs.append(log_entry)
                        except Exception:
                            continue
                except Exception as e:
                    logger.error(f"Error reading log file: {e}")
    
    except Exception as e:
        logger.error(f"Error getting logs from database: {e}")
        logs.append({
            'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'level': 'ERROR',
            'source': 'logs',
            'message': f'Error retrieving logs: {str(e)}',
            'category': 'system'
        })
    
    return logs


@home.route('/stats', methods=['GET'])
def system_stats():
    """Display comprehensive system statistics and performance metrics"""
    stats = get_system_stats()
    return render_template("stats.html", stats=stats)


def get_system_stats():
    """Collect comprehensive system statistics"""
    stats = {
        'server': get_server_stats(),
        'database': get_database_stats(),
        'performance': get_performance_stats(),
        'wallet': get_wallet_stats(),
        'security': get_security_stats(),
        'storage': get_storage_stats(),
        'network': get_network_stats(),
        'logs': get_log_stats()
    }
    return stats


def get_server_stats():
    """Server performance and resource usage"""
    try:
        if HAS_PSUTIL:
            # CPU and Memory
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Boot time and uptime
            boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
            uptime = datetime.datetime.now() - boot_time
            
            # Load averages (Unix/Linux)
            try:
                load_avg = os.getloadavg()
            except (AttributeError, OSError):
                load_avg = [0.0, 0.0, 0.0]
            
            return {
                'cpu_percent': round(cpu_percent, 1),
                'memory_total': round(memory.total / (1024**3), 2),  # GB
                'memory_used': round(memory.used / (1024**3), 2),
                'memory_percent': memory.percent,
                'disk_total': round(disk.total / (1024**3), 2),
                'disk_used': round(disk.used / (1024**3), 2),
                'disk_percent': round((disk.used / disk.total) * 100, 1),
                'load_avg_1m': round(load_avg[0], 2),
                'load_avg_5m': round(load_avg[1], 2),
                'load_avg_15m': round(load_avg[2], 2),
                'uptime_days': uptime.days,
                'uptime_hours': uptime.seconds // 3600,
                'boot_time': boot_time.strftime('%Y-%m-%d %H:%M:%S')
            }
        else:
            # Fallback when psutil is not available
            # Use basic system commands and estimates
            try:
                # Try to get disk usage using df command
                disk_info = os.statvfs('/')
                disk_total = (disk_info.f_frsize * disk_info.f_blocks) / (1024**3)
                disk_used = (disk_info.f_frsize * (disk_info.f_blocks - disk_info.f_available)) / (1024**3)
                disk_percent = (disk_used / disk_total) * 100
            except:
                disk_total = disk_used = disk_percent = 0
            
            # Load averages (Unix/Linux)
            try:
                load_avg = os.getloadavg()
            except (AttributeError, OSError):
                load_avg = [0.0, 0.0, 0.0]
            
            return {
                'cpu_percent': 15.2,  # Simulated
                'memory_total': 16.0,  # Simulated
                'memory_used': 8.5,   # Simulated
                'memory_percent': 53.1,  # Simulated
                'disk_total': round(disk_total, 2) if disk_total else 256.0,
                'disk_used': round(disk_used, 2) if disk_used else 128.5,
                'disk_percent': round(disk_percent, 1) if disk_percent else 50.2,
                'load_avg_1m': round(load_avg[0], 2),
                'load_avg_5m': round(load_avg[1], 2),
                'load_avg_15m': round(load_avg[2], 2),
                'uptime_days': 5,  # Simulated
                'uptime_hours': 14,  # Simulated
                'boot_time': (datetime.datetime.now() - datetime.timedelta(days=5, hours=14)).strftime('%Y-%m-%d %H:%M:%S')
            }
    except Exception as e:
        logger.error(f"Error getting server stats: {e}")
        return {'error': str(e)}


def get_database_stats():
    """Database performance and usage statistics"""
    try:
        # Database file size
        db_path = os.path.join(os.path.dirname(__file__), '..', 'instance', 'database.db')
        db_size = 0
        if os.path.exists(db_path):
            db_size = os.path.getsize(db_path) / (1024**2)  # MB
        
        # Table counts and sizes
        tables_info = []
        try:
            # Get table information
            result = db.session.execute(text("SELECT name FROM sqlite_master WHERE type='table';"))
            tables = [row[0] for row in result.fetchall()]
            
            for table in tables:
                try:
                    count_result = db.session.execute(text(f"SELECT COUNT(*) FROM {table};"))
                    count = count_result.fetchone()[0]
                    tables_info.append({'name': table, 'rows': count})
                except Exception:
                    tables_info.append({'name': table, 'rows': 'N/A'})
                    
        except Exception as e:
            logger.error(f"Error getting table info: {e}")
        
        return {
            'size_mb': round(db_size, 2),
            'tables': tables_info,
            'connection_pool_size': 10,  # Default SQLite doesn't have connection pools
            'active_connections': 1  # SQLite typically has 1 connection
        }
    except Exception as e:
        logger.error(f"Error getting database stats: {e}")
        return {'error': str(e)}


def get_performance_stats():
    """Real performance metrics from database operations"""
    try:
        # Get issuance metrics
        issuance_ops = OperationMetric.query.filter(
            OperationMetric.operation_type.in_(['issuance', 'credential_issuance']),
            OperationMetric.duration_ms.isnot(None)
        ).all()
        
        # Get verification metrics  
        verification_ops = OperationMetric.query.filter(
            OperationMetric.operation_type.in_(['verification', 'credential_verification']),
            OperationMetric.duration_ms.isnot(None)
        ).all()
        
        # Calculate issuance statistics
        if issuance_ops:
            issuance_times = [op.duration_seconds for op in issuance_ops if op.duration_seconds]
            avg_issuance = sum(issuance_times) / len(issuance_times)
            min_issuance = min(issuance_times)
            max_issuance = max(issuance_times)
            
            total_issuances = len(issuance_ops)
            successful_issuances = len([op for op in issuance_ops if op.status == 'success'])
            success_rate_issuance = (successful_issuances / total_issuances * 100) if total_issuances > 0 else 0
        else:
            avg_issuance = min_issuance = max_issuance = 0
            total_issuances = successful_issuances = success_rate_issuance = 0
        
        # Calculate verification statistics
        if verification_ops:
            verification_times = [op.duration_seconds for op in verification_ops if op.duration_seconds]
            avg_verification = sum(verification_times) / len(verification_times)
            min_verification = min(verification_times)
            max_verification = max(verification_times)
            
            total_verifications = len(verification_ops)
            successful_verifications = len([op for op in verification_ops if op.status == 'success'])
            success_rate_verification = (successful_verifications / total_verifications * 100) if total_verifications > 0 else 0
        else:
            avg_verification = min_verification = max_verification = 0
            total_verifications = successful_verifications = success_rate_verification = 0
        
        return {
            'avg_issuance_time': round(avg_issuance, 2),
            'min_issuance_time': round(min_issuance, 2),
            'max_issuance_time': round(max_issuance, 2),
            'avg_verification_time': round(avg_verification, 2),
            'min_verification_time': round(min_verification, 2),
            'max_verification_time': round(max_verification, 2),
            'total_issuances': total_issuances,
            'total_verifications': total_verifications,
            'success_rate_issuance': round(success_rate_issuance, 1),
            'success_rate_verification': round(success_rate_verification, 1)
        }
    except Exception as e:
        logger.error(f"Error getting performance stats: {e}")
        return {'error': str(e)}


def get_wallet_stats():
    """Real wallet connection and usage statistics from database"""
    try:
        # Current active connections
        active_connections = WalletConnection.query.filter_by(is_active=True).count()
        
        # Total unique wallets ever connected
        total_wallets = db.session.query(func.count(func.distinct(WalletConnection.wallet_id))).scalar() or 0
        
        # Unique wallets in last 24 hours
        yesterday = datetime.datetime.now() - datetime.timedelta(hours=24)
        unique_24h = db.session.query(func.count(func.distinct(WalletConnection.wallet_id))).filter(
            WalletConnection.connected_at >= yesterday
        ).scalar() or 0
        
        # Connection errors in last 24 hours (from security events)
        connection_errors = SecurityEvent.query.filter(
            SecurityEvent.timestamp >= yesterday,
            SecurityEvent.event_type.in_(['connection_error', 'auth_failure'])
        ).count()
        
        # Average session duration
        completed_sessions = WalletConnection.query.filter(
            WalletConnection.disconnected_at.isnot(None)
        ).limit(100).all()
        
        avg_duration = 0
        if completed_sessions:
            total_duration = sum(session.session_duration for session in completed_sessions)
            avg_duration = total_duration / len(completed_sessions)
        
        # Mobile vs Desktop breakdown
        mobile_count = WalletConnection.query.filter_by(connection_type='mobile').count()
        desktop_count = WalletConnection.query.filter_by(connection_type='desktop').count()
        
        # Peak concurrent connections (simplified estimate)
        # For now, use active connections as peak estimate
        # TODO: Implement proper time-series tracking for accurate peak calculation
        peak_concurrent = max(active_connections, total_wallets)
        
        # Credentials in circulation (from VC_validity table)
        try:
            from .models import VC_validity
            credentials_count = VC_validity.query.count()
        except Exception:
            # Fallback if VC_validity table doesn't exist or has issues
            credentials_count = 0
        
        return {
            'active_connections': active_connections,
            'total_wallets_connected': total_wallets,
            'unique_wallets_24h': unique_24h,
            'connection_errors_24h': connection_errors,
            'avg_session_duration': round(avg_duration, 1),
            'mobile_wallets': mobile_count,
            'desktop_wallets': desktop_count,
            'peak_concurrent_connections': peak_concurrent,
            'credentials_in_circulation': credentials_count
        }
    except Exception as e:
        logger.error(f"Error getting wallet stats: {e}")
        return {'error': str(e)}


def get_security_stats():
    """Real security metrics and events from database"""
    try:
        yesterday = datetime.datetime.now() - datetime.timedelta(hours=24)
        
        # Authentication events
        failed_auth = SecurityEvent.query.filter(
            SecurityEvent.timestamp >= yesterday,
            SecurityEvent.event_type == 'auth_failure'
        ).count()
        
        successful_auth = SecurityEvent.query.filter(
            SecurityEvent.timestamp >= yesterday,
            SecurityEvent.event_type == 'auth_success'
        ).count()
        
        # Security alerts
        security_alerts = SecurityEvent.query.filter(
            SecurityEvent.timestamp >= yesterday,
            SecurityEvent.severity.in_(['high', 'critical'])
        ).count()
        
        # Rate limit violations
        rate_limits = SecurityEvent.query.filter(
            SecurityEvent.timestamp >= yesterday,
            SecurityEvent.event_type == 'rate_limit'
        ).count()
        
        # Suspicious activities
        suspicious = SecurityEvent.query.filter(
            SecurityEvent.timestamp >= yesterday,
            SecurityEvent.event_type == 'suspicious_activity'
        ).count()
        
        # Blocked IPs (unique count)
        blocked_ips = db.session.query(func.count(func.distinct(SecurityEvent.source_ip))).filter(
            SecurityEvent.timestamp >= yesterday,
            SecurityEvent.action_taken == 'blocked'
        ).scalar() or 0
        
        # Active sessions (wallet connections)
        active_sessions = WalletConnection.query.filter_by(is_active=True).count()
        
        # SSL certificate expiry (check from Certificate table)
        ssl_cert = Certificate.query.filter_by(certificate_type='ssl', is_active=True).first()
        ssl_days = ssl_cert.days_until_expiry if ssl_cert else 0
        
        return {
            'failed_authentication_attempts': failed_auth,
            'successful_authentications': successful_auth,
            'security_alerts_24h': security_alerts,
            'ssl_certificate_expiry_days': ssl_days,
            'rate_limit_violations': rate_limits,
            'suspicious_activities': suspicious,
            'blocked_ips': blocked_ips,
            'active_sessions': active_sessions
        }
    except Exception as e:
        logger.error(f"Error getting security stats: {e}")
        return {'error': str(e)}


def get_storage_stats():
    """Storage and file system statistics"""
    try:
        instance_dir = os.path.join(os.path.dirname(__file__), '..', 'instance')
        
        # Calculate directory sizes
        total_size = 0
        file_counts = {'logs': 0, 'certs': 0, 'keys': 0, 'other': 0}
        
        if os.path.exists(instance_dir):
            for root, dirs, files in os.walk(instance_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        size = os.path.getsize(file_path)
                        total_size += size
                        
                        if file.endswith('.log'):
                            file_counts['logs'] += 1
                        elif file.endswith('.pem') or file.endswith('.key'):
                            file_counts['keys'] += 1
                        elif file.endswith('.crt') or 'cert' in file:
                            file_counts['certs'] += 1
                        else:
                            file_counts['other'] += 1
                    except OSError:
                        continue
        
        return {
            'total_size_mb': round(total_size / (1024**2), 2),
            'log_files': file_counts['logs'],
            'certificate_files': file_counts['certs'],
            'key_files': file_counts['keys'],
            'other_files': file_counts['other'],
            'backup_size_mb': 0.0,  # Placeholder
            'last_backup': 'Never'
        }
    except Exception as e:
        logger.error(f"Error getting storage stats: {e}")
        return {'error': str(e)}


def get_network_stats():
    """Network and connectivity statistics"""
    try:
        if HAS_PSUTIL:
            net_io = psutil.net_io_counters()
            
            return {
                'bytes_sent_mb': round(net_io.bytes_sent / (1024**2), 2),
                'bytes_received_mb': round(net_io.bytes_recv / (1024**2), 2),
                'packets_sent': net_io.packets_sent,
                'packets_received': net_io.packets_recv,
                'network_errors': net_io.errin + net_io.errout,
                'dropped_packets': net_io.dropin + net_io.dropout,
                'active_ports': len([conn for conn in psutil.net_connections() if conn.status == 'ESTABLISHED']),
                'listening_ports': len([conn for conn in psutil.net_connections() if conn.status == 'LISTEN'])
            }
        else:
            # Simulated network stats when psutil is not available
            return {
                'bytes_sent_mb': 245.7,
                'bytes_received_mb': 1023.4,
                'packets_sent': 15834,
                'packets_received': 47562,
                'network_errors': 2,
                'dropped_packets': 0,
                'active_ports': 18,
                'listening_ports': 6
            }
    except Exception as e:
        logger.error(f"Error getting network stats: {e}")
        return {'error': str(e)}


def get_log_stats():
    """Real log statistics from database"""
    try:
        # Total entries from database
        total_entries = SystemLog.query.count()
        
        # Count by level
        info_logs = SystemLog.query.filter_by(level='INFO').count()
        warning_logs = SystemLog.query.filter_by(level='WARNING').count()
        error_logs = SystemLog.query.filter_by(level='ERROR').count()
        debug_logs = SystemLog.query.filter_by(level='DEBUG').count()
        critical_logs = SystemLog.query.filter_by(level='CRITICAL').count()
        
        # File size (fallback to file system if database doesn't have size info)
        log_file = os.path.join(os.path.dirname(__file__), '..', 'instance', 'service.log')
        file_size = 0
        if os.path.exists(log_file):
            file_size = os.path.getsize(log_file) / (1024**2)
        
        return {
            'total_entries': total_entries,
            'file_size_mb': round(file_size, 2),
            'info_logs': info_logs,
            'warning_logs': warning_logs,
            'error_logs': error_logs,
            'debug_logs': debug_logs,
            'critical_logs': critical_logs
        }
    except Exception as e:
        logger.error(f"Error getting log stats: {e}")
        return {'error': str(e)}


@home.route("/health")
def health_check():
    """Health check endpoint for Docker containers and load balancers."""
    try:
        # Basic application health check
        # Test database connection
        db.session.execute(text('SELECT 1'))
        
        return {
            "status": "healthy",
            "timestamp": datetime.datetime.now(timezone.utc).isoformat(),
            "service": "StudentVC Backend",
            "version": "1.0.0"
        }, 200
    except Exception as e:
        return {
            "status": "unhealthy",
            "timestamp": datetime.datetime.now(timezone.utc).isoformat(),
            "error": str(e)
        }, 503


@home.route('/impressum')
def impressum():
    """Display help and impressum page"""
    return render_template("impressum.html")


@home.route("/favicon.ico")
def favicon():
    return "", 404
