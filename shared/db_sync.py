# shared/db_sync.py

import requests
from sqlalchemy.orm import Session
from shared.models import User, Credential
from shared.encryption import encrypt_data, decrypt_data
import json

class DatabaseSynchronizer:
    def __init__(self, local_session: Session, remote_url: str, api_key: str):
        self.local_session = local_session
        self.remote_url = remote_url
        self.headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {api_key}'
        }

    def sync_to_remote(self, user: User):
        local_credentials = self.local_session.query(Credential).filter_by(user_id=user.id).all()
        
        for cred in local_credentials:
            payload = {
                'name': cred.name,
                'data': cred.data,  # This is already encrypted
                'last_modified': str(cred.updated_at)
            }
            
            response = requests.post(f"{self.remote_url}/api/sync_credential", 
                                     headers=self.headers, 
                                     data=json.dumps(payload))
            
            if response.status_code != 200:
                print(f"Failed to sync credential {cred.name}: {response.text}")

    def sync_from_remote(self, user: User):
        response = requests.get(f"{self.remote_url}/api/get_credentials", headers=self.headers)
        
        if response.status_code == 200:
            remote_credentials = response.json()
            
            for remote_cred in remote_credentials:
                local_cred = self.local_session.query(Credential).filter_by(name=remote_cred['name'], user_id=user.id).first()
                
                if not local_cred:
                    new_cred = Credential(name=remote_cred['name'], 
                                          data=remote_cred['data'],
                                          user_id=user.id)
                    self.local_session.add(new_cred)
                elif remote_cred['last_modified'] > str(local_cred.updated_at):
                    local_cred.data = remote_cred['data']
                    local_cred.updated_at = remote_cred['last_modified']
            
            self.local_session.commit()
        else:
            print(f"Failed to fetch credentials from remote: {response.text}")

    def perform_full_sync(self, user: User):
        self.sync_to_remote(user)
        self.sync_from_remote(user)