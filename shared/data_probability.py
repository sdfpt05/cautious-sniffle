import json
import csv
import os
from datetime import datetime
from cryptography.fernet import Fernet
import logging

logger = logging.getLogger(__name__)

class DataPortabilityManager:
    """Manages import and export of credentials for data portability"""
    
    def __init__(self, session, user, encryption_key):
        self.session = session
        self.user = user
        self.encryption_key = encryption_key
        self.fernet = Fernet(encryption_key)
    
    def export_to_json(self, output_path, encrypt_export=True):
        """
        Export user credentials to a JSON file
        
        Args:
            output_path: Path where the file will be saved
            encrypt_export: Whether to encrypt the exported file
            
        Returns:
            tuple: (success, message)
        """
        try:
            from shared.models import Credential
            
            credentials = self.session.query(Credential).filter_by(user_id=self.user.id).all()
            
            export_data = {
                'metadata': {
                    'export_date': datetime.now().isoformat(),
                    'username': self.user.username,
                    'email': self.user.email,
                    'credential_count': len(credentials)
                },
                'credentials': []
            }
            
            for cred in credentials:
                # Decrypt the data for export
                decrypted_data = self.fernet.decrypt(cred.encrypted_data.encode()).decode()
                
                credential_data = {
                    'name': cred.name,
                    'data': decrypted_data,
                    'category': cred.category,
                    'url': cred.url,
                    'notes': cred.notes,
                    'favorite': cred.favorite,
                    'created_at': cred.created_at.isoformat() if cred.created_at else None,
                    'updated_at': cred.updated_at.isoformat() if cred.updated_at else None
                }
                
                export_data['credentials'].append(credential_data)
            
            if encrypt_export:
                # Encrypt the entire export
                export_json = json.dumps(export_data)
                encrypted_export = self.fernet.encrypt(export_json.encode())
                
                with open(output_path, 'wb') as f:
                    f.write(encrypted_export)
                
                return True, f"Encrypted export saved to {output_path}"
            else:
                # Save as plain JSON
                with open(output_path, 'w') as f:
                    json.dump(export_data, f, indent=2)
                
                return True, f"Export saved to {output_path}"
                
        except Exception as e:
            logger.error(f"Error exporting data: {str(e)}")
            return False, f"Error exporting data: {str(e)}"
    
    def export_to_csv(self, output_path):
        """
        Export user credentials to a CSV file
        
        Args:
            output_path: Path where the file will be saved
            
        Returns:
            tuple: (success, message)
        """
        try:
            from shared.models import Credential
            
            credentials = self.session.query(Credential).filter_by(user_id=self.user.id).all()
            
            with open(output_path, 'w', newline='') as csvfile:
                fieldnames = ['name', 'data', 'category', 'url', 'notes', 'favorite', 'created_at', 'updated_at']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                for cred in credentials:
                    # Decrypt the data for export
                    decrypted_data = self.fernet.decrypt(cred.encrypted_data.encode()).decode()
                    
                    writer.writerow({
                        'name': cred.name,
                        'data': decrypted_data,
                        'category': cred.category or '',
                        'url': cred.url or '',
                        'notes': cred.notes or '',
                        'favorite': 'Yes' if cred.favorite else 'No',
                        'created_at': cred.created_at.isoformat() if cred.created_at else '',
                        'updated_at': cred.updated_at.isoformat() if cred.updated_at else ''
                    })
            
            return True, f"Export saved to {output_path}"
            
        except Exception as e:
            logger.error(f"Error exporting data to CSV: {str(e)}")
            return False, f"Error exporting data: {str(e)}"
    
    def import_from_json(self, input_path, is_encrypted=True, replace_existing=False):
        """
        Import credentials from a JSON file
        
        Args:
            input_path: Path to the JSON file
            is_encrypted: Whether the file is encrypted
            replace_existing: Whether to replace existing credentials with the same name
            
        Returns:
            tuple: (success, message)
        """
        try:
            from shared.models import Credential
            
            if is_encrypted:
                # Read and decrypt the file
                with open(input_path, 'rb') as f:
                    encrypted_data = f.read()
                
                decrypted_json = self.fernet.decrypt(encrypted_data).decode()
                import_data = json.loads(decrypted_json)
            else:
                # Read plain JSON
                with open(input_path, 'r') as f:
                    import_data = json.load(f)
            
            if 'credentials' not in import_data:
                return False, "Invalid import file format"
            
            imported_count = 0
            skipped_count = 0
            
            for cred_data in import_data['credentials']:
                name = cred_data.get('name')
                if not name:
                    skipped_count += 1
                    continue
                
                # Check if credential already exists
                existing_cred = self.session.query(Credential).filter_by(
                    name=name, 
                    user_id=self.user.id
                ).first()
                
                if existing_cred and not replace_existing:
                    skipped_count += 1
                    continue
                
                # Encrypt the credential data
                encrypted_data = self.fernet.encrypt(cred_data.get('data', '').encode())
                
                if existing_cred:
                    # Update existing
                    existing_cred.encrypted_data = encrypted_data
                    existing_cred.category = cred_data.get('category')
                    existing_cred.url = cred_data.get('url')
                    existing_cred.notes = cred_data.get('notes')
                    existing_cred.favorite = cred_data.get('favorite', False)
                else:
                    # Create new
                    new_cred = Credential(
                        name=name,
                        encrypted_data=encrypted_data,
                        user_id=self.user.id,
                        category=cred_data.get('category'),
                        url=cred_data.get('url'),
                        notes=cred_data.get('notes'),
                        favorite=cred_data.get('favorite', False)
                    )
                    self.session.add(new_cred)
                
                imported_count += 1
            
            self.session.commit()
            
            return True, f"Imported {imported_count} credentials, skipped {skipped_count}"
            
        except Exception as e:
            self.session.rollback()
            logger.error(f"Error importing data: {str(e)}")
            return False, f"Error importing data: {str(e)}"
    
    def import_from_csv(self, input_path, replace_existing=False):
        """
        Import credentials from a CSV file
        
        Args:
            input_path: Path to the CSV file
            replace_existing: Whether to replace existing credentials with the same name
            
        Returns:
            tuple: (success, message)
        """
        try:
            from shared.models import Credential
            
            imported_count = 0
            skipped_count = 0
            
            with open(input_path, 'r', newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                
                for row in reader:
                    name = row.get('name')
                    if not name:
                        skipped_count += 1
                        continue
                    
                    # Check if credential already exists
                    existing_cred = self.session.query(Credential).filter_by(
                        name=name, 
                        user_id=self.user.id
                    ).first()
                    
                    if existing_cred and not replace_existing:
                        skipped_count += 1
                        continue
                    
                    # Encrypt the credential data
                    encrypted_data = self.fernet.encrypt(row.get('data', '').encode())
                    
                    if existing_cred:
                        # Update existing
                        existing_cred.encrypted_data = encrypted_data
                        existing_cred.category = row.get('category')
                        existing_cred.url = row.get('url')
                        existing_cred.notes = row.get('notes')
                        existing_cred.favorite = row.get('favorite', '').lower() == 'yes'
                    else:
                        # Create new
                        new_cred = Credential(
                            name=name,
                            encrypted_data=encrypted_data,
                            user_id=self.user.id,
                            category=row.get('category'),
                            url=row.get('url'),
                            notes=row.get('notes'),
                            favorite=row.get('favorite', '').lower() == 'yes'
                        )
                        self.session.add(new_cred)
                    
                    imported_count += 1
            
            self.session.commit()
            
            return True, f"Imported {imported_count} credentials, skipped {skipped_count}"
            
        except Exception as e:
            self.session.rollback()
            logger.error(f"Error importing data from CSV: {str(e)}")
            return False, f"Error importing data: {str(e)}"