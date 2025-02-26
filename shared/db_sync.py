# shared/db_sync.py
import requests
from sqlalchemy.orm import Session
from shared.models import User, Credential, AuditLog
import json
from datetime import datetime
import time
import logging

logger = logging.getLogger(__name__)

class DatabaseSynchronizer:
    """Handles synchronization of credentials between local and remote databases"""
    
    def __init__(self, local_session: Session, remote_url: str, api_key: str):
        self.local_session = local_session
        self.remote_url = remote_url
        self.headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {api_key}'
        }
        self.last_sync_time = None
    
    def sync_to_remote(self, user: User, log_action=True):
        """
        Sync local credentials to the remote server
        
        Args:
            user: The user whose credentials should be synced
            log_action: Whether to log the sync action
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            local_credentials = self.local_session.query(Credential).filter_by(user_id=user.id).all()
            
            for cred in local_credentials:
                payload = {
                    'name': cred.name,
                    'data': cred.encrypted_data,
                    'category': cred.category,
                    'url': cred.url,
                    'notes': cred.notes,
                    'favorite': cred.favorite,
                    'last_modified': str(cred.updated_at)
                }
                
                response = requests.post(
                    f"{self.remote_url}/api/sync_credential", 
                    headers=self.headers, 
                    data=json.dumps(payload),
                    timeout=10
                )
                
                if response.status_code != 200:
                    logger.error(f"Failed to sync credential {cred.name}: {response.text}")
            
            if log_action:
                self._log_sync_action(user.id, "sync_to_remote", "Synced credentials to remote server")
            
            self.last_sync_time = datetime.now()
            return True
            
        except requests.RequestException as e:
            logger.error(f"Error syncing to remote: {str(e)}")
            return False
    
    def sync_from_remote(self, user: User, log_action=True):
        """
        Sync credentials from remote server to local database
        
        Args:
            user: The user whose credentials should be synced
            log_action: Whether to log the sync action
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            response = requests.get(
                f"{self.remote_url}/api/get_credentials", 
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code == 200:
                remote_credentials = response.json()
                
                for remote_cred in remote_credentials:
                    local_cred = self.local_session.query(Credential).filter_by(
                        name=remote_cred['name'], 
                        user_id=user.id
                    ).first()
                    
                    remote_modified = datetime.fromisoformat(remote_cred['last_modified'])
                    
                    if not local_cred:
                        # Create new credential locally
                        new_cred = Credential(
                            name=remote_cred['name'],
                            encrypted_data=remote_cred['data'],
                            user_id=user.id,
                            category=remote_cred.get('category'),
                            url=remote_cred.get('url'),
                            notes=remote_cred.get('notes'),
                            favorite=remote_cred.get('favorite', False)
                        )
                        self.local_session.add(new_cred)
                    elif not local_cred.updated_at or remote_modified > local_cred.updated_at:
                        # Update existing credential if remote is newer
                        local_cred.encrypted_data = remote_cred['data']
                        local_cred.category = remote_cred.get('category', local_cred.category)
                        local_cred.url = remote_cred.get('url', local_cred.url)
                        local_cred.notes = remote_cred.get('notes', local_cred.notes)
                        local_cred.favorite = remote_cred.get('favorite', local_cred.favorite)
                        local_cred.updated_at = remote_modified
                
                self.local_session.commit()
                
                if log_action:
                    self._log_sync_action(user.id, "sync_from_remote", 
                                          f"Synced {len(remote_credentials)} credentials from remote server")
                
                self.last_sync_time = datetime.now()
                return True
            else:
                logger.error(f"Failed to fetch credentials from remote: {response.text}")
                return False
                
        except requests.RequestException as e:
            logger.error(f"Error syncing from remote: {str(e)}")
            return False
    
    def perform_full_sync(self, user: User):
        """
        Perform a full two-way sync with the remote server
        
        Args:
            user: The user whose credentials should be synced
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # First sync from remote to get the latest updates
            remote_success = self.sync_from_remote(user, log_action=False)
            
            # Then sync to remote with our local changes
            local_success = self.sync_to_remote(user, log_action=False)
            
            # Log the combined sync action
            self._log_sync_action(user.id, "full_sync", 
                                 f"Performed full sync. Remote sync: {'Success' if remote_success else 'Failure'}, "
                                 f"Local sync: {'Success' if local_success else 'Failure'}")
            
            self.last_sync_time = datetime.now()
            return remote_success and local_success
            
        except Exception as e:
            logger.error(f"Error during full sync: {str(e)}")
            return False
    
    def _log_sync_action(self, user_id, action, details):
        """Log a sync action to the audit log"""
        log_entry = AuditLog(
            user_id=user_id,
            action=action,
            details=details
        )
        self.local_session.add(log_entry)
        self.local_session.commit()
    
    def auto_sync(self, user: User, interval_minutes=15):
        """
        Check if it's time to sync and perform sync if needed
        
        Args:
            user: The user whose credentials should be synced
            interval_minutes: How often to sync in minutes
        
        Returns:
            bool: True if sync was performed, False otherwise
        """
        if not self.last_sync_time or (datetime.now() - self.last_sync_time).total_seconds() >= interval_minutes * 60:
            return self.perform_full_sync(user)
        return False