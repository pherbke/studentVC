"""
StudentVC Logging System
Comprehensive logging with categorization and filtering for:
- Issuance processes
- Revocations
- Verifications
- Authentication events
- System operations
"""

import logging
import json
import datetime
from datetime import timezone
from enum import Enum
from typing import Dict, Any, Optional, List
from flask import g, request
import os
from functools import wraps

class LogCategory(Enum):
    """Log categories for filtering"""
    ISSUANCE = "issuance"
    REVOCATION = "revocation"
    VERIFICATION = "verification"
    AUTHENTICATION = "authentication"
    SYSTEM = "system"
    ERROR = "error"
    SECURITY = "security"
    PERFORMANCE = "performance"

class LogLevel(Enum):
    """Log levels"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

class StudentVCLogger:
    """Enhanced logging system for StudentVC"""
    
    def __init__(self, log_dir: str = "logs"):
        self.log_dir = log_dir
        self.ensure_log_directory()
        self.setup_loggers()
        
    def ensure_log_directory(self):
        """Create log directory if it doesn't exist"""
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
            
    def setup_loggers(self):
        """Setup category-specific loggers"""
        # Main application logger
        self.main_logger = self._create_logger("studentvc.main", "main.log")
        
        # Category-specific loggers
        self.issuance_logger = self._create_logger("studentvc.issuance", "issuance.log")
        self.revocation_logger = self._create_logger("studentvc.revocation", "revocation.log")
        self.verification_logger = self._create_logger("studentvc.verification", "verification.log")
        self.auth_logger = self._create_logger("studentvc.auth", "authentication.log")
        self.security_logger = self._create_logger("studentvc.security", "security.log")
        self.performance_logger = self._create_logger("studentvc.performance", "performance.log")
        
        # Error logger (goes to all)
        self.error_logger = self._create_logger("studentvc.error", "errors.log")
        
    def _create_logger(self, name: str, filename: str) -> logging.Logger:
        """Create a logger with file and console handlers"""
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)
        
        # Prevent duplicate handlers
        if logger.handlers:
            return logger
            
        # File handler
        file_handler = logging.FileHandler(os.path.join(self.log_dir, filename))
        file_handler.setLevel(logging.DEBUG)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # JSON formatter for structured logging
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
        
    def _get_request_context(self) -> Dict[str, Any]:
        """Extract request context for logging"""
        context = {
            "timestamp": datetime.datetime.now(timezone.utc).isoformat(),
            "request_id": getattr(g, 'request_id', None),
        }
        
        try:
            context.update({
                "ip_address": request.remote_addr,
                "user_agent": request.headers.get('User-Agent'),
                "method": request.method,
                "url": request.url,
                "endpoint": request.endpoint,
            })
        except RuntimeError:
            # Outside request context
            pass
            
        return context
        
    def log(self, category: LogCategory, level: LogLevel, message: str, 
            extra_data: Optional[Dict[str, Any]] = None, 
            credential_id: Optional[str] = None,
            tenant: Optional[str] = None):
        """Main logging method"""
        
        # Prepare log data
        log_data = {
            "category": category.value,
            "level": level.value,
            "message": message,
            "context": self._get_request_context(),
        }
        
        if extra_data:
            log_data["extra"] = extra_data
            
        if credential_id:
            log_data["credential_id"] = credential_id
            
        if tenant:
            log_data["tenant"] = tenant
            
        # Convert to JSON string
        log_message = json.dumps(log_data, default=str)
        
        # Route to appropriate logger
        logger = self._get_category_logger(category)
        
        # Log at appropriate level
        if level == LogLevel.DEBUG:
            logger.debug(log_message)
        elif level == LogLevel.INFO:
            logger.info(log_message)
        elif level == LogLevel.WARNING:
            logger.warning(log_message)
        elif level == LogLevel.ERROR:
            logger.error(log_message)
            # Also log to error logger
            self.error_logger.error(log_message)
        elif level == LogLevel.CRITICAL:
            logger.critical(log_message)
            # Also log to error logger
            self.error_logger.critical(log_message)
            
    def _get_category_logger(self, category: LogCategory) -> logging.Logger:
        """Get logger for specific category"""
        mapping = {
            LogCategory.ISSUANCE: self.issuance_logger,
            LogCategory.REVOCATION: self.revocation_logger,
            LogCategory.VERIFICATION: self.verification_logger,
            LogCategory.AUTHENTICATION: self.auth_logger,
            LogCategory.SECURITY: self.security_logger,
            LogCategory.PERFORMANCE: self.performance_logger,
            LogCategory.ERROR: self.error_logger,
            LogCategory.SYSTEM: self.main_logger,
        }
        return mapping.get(category, self.main_logger)
        
    # Convenience methods for different categories
    def log_issuance(self, message: str, level: LogLevel = LogLevel.INFO, 
                    credential_id: str = None, tenant: str = None, **kwargs):
        """Log credential issuance events"""
        self.log(LogCategory.ISSUANCE, level, message, kwargs, credential_id, tenant)
        
    def log_revocation(self, message: str, level: LogLevel = LogLevel.INFO,
                      credential_id: str = None, tenant: str = None, **kwargs):
        """Log credential revocation events"""
        self.log(LogCategory.REVOCATION, level, message, kwargs, credential_id, tenant)
        
    def log_verification(self, message: str, level: LogLevel = LogLevel.INFO,
                        credential_id: str = None, tenant: str = None, **kwargs):
        """Log credential verification events"""
        self.log(LogCategory.VERIFICATION, level, message, kwargs, credential_id, tenant)
        
    def log_auth(self, message: str, level: LogLevel = LogLevel.INFO,
                user_id: str = None, tenant: str = None, **kwargs):
        """Log authentication events"""
        if user_id:
            kwargs['user_id'] = user_id
        self.log(LogCategory.AUTHENTICATION, level, message, kwargs, tenant=tenant)
        
    def log_security(self, message: str, level: LogLevel = LogLevel.WARNING,
                    tenant: str = None, **kwargs):
        """Log security events"""
        self.log(LogCategory.SECURITY, level, message, kwargs, tenant=tenant)
        
    def log_performance(self, message: str, execution_time: float = None,
                       tenant: str = None, **kwargs):
        """Log performance metrics"""
        if execution_time:
            kwargs['execution_time_ms'] = execution_time * 1000
        self.log(LogCategory.PERFORMANCE, LogLevel.INFO, message, kwargs, tenant=tenant)
        
    def log_error(self, message: str, error: Exception = None, 
                 tenant: str = None, **kwargs):
        """Log errors with exception details"""
        if error:
            kwargs.update({
                'exception_type': type(error).__name__,
                'exception_message': str(error),
                'exception_args': error.args
            })
        self.log(LogCategory.ERROR, LogLevel.ERROR, message, kwargs, tenant=tenant)

# Global logger instance
logger_instance = StudentVCLogger()

def log_function_call(category: LogCategory, include_args: bool = False):
    """Decorator to automatically log function calls"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            func_name = f"{func.__module__}.{func.__name__}"
            
            log_data = {
                "function": func_name,
            }
            
            if include_args:
                log_data.update({
                    "args": str(args),
                    "kwargs": {k: str(v) for k, v in kwargs.items()}
                })
            
            # Log function start
            logger_instance.log(
                category, 
                LogLevel.DEBUG, 
                f"Function {func_name} called",
                log_data
            )
            
            try:
                # Execute function with timing
                start_time = datetime.datetime.now(timezone.utc)
                result = func(*args, **kwargs)
                end_time = datetime.datetime.now(timezone.utc)
                
                # Log successful completion
                execution_time = (end_time - start_time).total_seconds()
                logger_instance.log_performance(
                    f"Function {func_name} completed successfully",
                    execution_time=execution_time
                )
                
                return result
                
            except Exception as e:
                # Log error
                logger_instance.log_error(
                    f"Function {func_name} failed",
                    error=e
                )
                raise
                
        return wrapper
    return decorator

# Convenience functions for direct use
def log_issuance(message: str, **kwargs):
    """Direct issuance logging"""
    logger_instance.log_issuance(message, **kwargs)

def log_revocation(message: str, **kwargs):
    """Direct revocation logging"""
    logger_instance.log_revocation(message, **kwargs)

def log_verification(message: str, **kwargs):
    """Direct verification logging"""
    logger_instance.log_verification(message, **kwargs)

def log_auth(message: str, **kwargs):
    """Direct authentication logging"""
    logger_instance.log_auth(message, **kwargs)

def log_security(message: str, **kwargs):
    """Direct security logging"""
    logger_instance.log_security(message, **kwargs)

def log_error(message: str, error: Exception = None, **kwargs):
    """Direct error logging"""
    logger_instance.log_error(message, error=error, **kwargs)