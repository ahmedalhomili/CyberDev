"""
Session logging and persistence module.
Manages scan history and session data storage.
"""
import json
import os
import uuid
from datetime import datetime
from typing import List, Dict, Optional, Union

from models import ScanResult


# Ensure we can import from parent if needed, though relative imports are preferred within packages.
# For simplicity in this structure, we'll assume proper path setup.
    
class SessionLogger:
    """Manages scan session logging and persistence."""
    
    SESSIONS_DIR = os.path.join(os.getcwd(), 'sessions', 'scan_sessions')
    
    def __init__(self, sessions_dir: str = None):
        """
        Initialize session logger.
        
        Args:
            sessions_dir: Directory for storing session logs
        """
        if sessions_dir:
            self.sessions_dir = sessions_dir
        else:
            self.sessions_dir = self.SESSIONS_DIR
            
        self._ensure_sessions_directory()
    
    def _ensure_sessions_directory(self):
        """Create sessions directory if it doesn't exist."""
        if not os.path.exists(self.sessions_dir):
            os.makedirs(self.sessions_dir, exist_ok=True)
    
    def generate_session_id(self, domain: str = "target") -> str:
        """
        Generate unique session ID.
        
        Format: SWVC-YYYYMMDD-HHMMSS-UUID (short)
        Example: SWVC-20240115-093045-a7f3e2b1
        """
        timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        unique_part = str(uuid.uuid4())[:8]
        # Clean domain for filename safety
        params = domain.replace("https://", "").replace("http://", "").split("/")[0]
        safe_domain = "".join(x for x in params if x.isalnum() or x in "._-")
        
        return f"SWVC-{timestamp}-{safe_domain}-{unique_part}"
    
    def get_timestamp(self) -> datetime:
        """Get current timestamp."""
        return datetime.now()
    
    def save_session(self, scan_result: Union[ScanResult, Dict]) -> str:
        """
        Save scan session to JSON file.
        
        Args:
            scan_result: ScanResult object or Dictionary to persist
            
        Returns:
            Path to saved session file
        """
        if isinstance(scan_result, ScanResult):
            session_id = scan_result.session_id
            session_data = scan_result.to_dict()
        else:
            session_id = scan_result.get('session_id')
            session_data = scan_result
            
        session_filename = f"{session_id}.json"
        session_filepath = os.path.join(self.sessions_dir, session_filename)
        
        try:
            with open(session_filepath, 'w', encoding='utf-8') as f:
                json.dump(session_data, f, indent=2)
            return session_filepath
        except Exception as e:
            print(f"Failed to save session: {str(e)}")
            raise
    
    def load_session(self, session_id: str) -> Optional[Dict]:
        """
        Load a session from file.
        
        Args:
            session_id: Session ID to load
            
        Returns:
            Session data as dictionary
        """
        # Handle if user passed full filename or just ID
        if not session_id.endswith('.json'):
            session_filename = f"{session_id}.json"
        else:
            session_filename = session_id
            
        session_filepath = os.path.join(self.sessions_dir, session_filename)
        
        if not os.path.exists(session_filepath):
            return None
        
        try:
            with open(session_filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Failed to load session: {str(e)}")
            return None
    
    def list_sessions(self, limit: int = 10) -> List[Dict]:
        """
        List recent scan sessions.
        
        Args:
            limit: Maximum number of sessions to return
            
        Returns:
            List of session metadata dictionaries
        """
        sessions = []
        
        try:
            if not os.path.exists(self.sessions_dir):
                return []
                
            files = sorted(os.listdir(self.sessions_dir), reverse=True)
            count = 0
            for filename in files:
                if filename.endswith('.json') and count < limit:
                    # Parse filename for timestamp to avoid opening all files if possible? 
                    # No, safer to read content for accurate metadata but might be slow.
                    # For simple listing let's just use filenames if they have timestamps, 
                    # but the guide says "load_session" to get details.
                    try:
                        session_data = self.load_session(filename)
                        if session_data:
                            summary = session_data.get('summary', {'total': 0})
                            sessions.append({
                                'session_id': session_data.get('session_id'),
                                'target_url': session_data.get('target_url'),
                                'timestamp': session_data.get('timestamp'),
                                'total_findings': summary.get('total', 0)
                            })
                            count += 1
                    except Exception:
                        continue
        except Exception as e:
            print(f"Error listing sessions: {str(e)}")
        
        return sessions

    def delete_history(self):
        """Delete all session files."""
        if os.path.exists(self.sessions_dir):
            for f in os.listdir(self.sessions_dir):
                if f.endswith(".json"):
                    os.remove(os.path.join(self.sessions_dir, f))
