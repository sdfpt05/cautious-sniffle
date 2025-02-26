import click
from sqlalchemy.orm import sessionmaker
from getpass import getpass
from shared.models import User, Credential, AuditLog, init_db
from sqlalchemy.exc import IntegrityError
from shared.encryption import generate_key, encrypt_data, decrypt_data
from colorama import Fore, Style
import re
import sys
import os
from shared.db_sync import DatabaseSynchronizer
from shared.password_checker import PasswordValidator
from shared.mfa import MFAManager
from shared.data_portability import DataPortabilityManager
import pyotp
import datetime
import logging
import traceback

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='data_vault_cli.log'
)
logger = logging.getLogger(__name__)

def safe_db_operation(func):
    """Decorator to handle database operation errors"""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            click.echo(Fore.RED + f"Database error: {str(e)}" + Style.RESET_ALL)
            logger.error(f"Database error in {func.__name__}: {str(e)}")
            logger.debug(traceback.format_exc())
            return None
    return wrapper

def print_menu():
    """Print the main menu options"""
    click.echo("\n" + Fore.CYAN + "Data Privacy Vault - Main Menu:" + Style.RESET_ALL)
    click.echo("1. View Credentials")
    click.echo("2. Add Credential")
    click.echo("3. Update Credential")
    click.echo("4. Delete Credential")
    click.echo("5. Generate Strong Password")
    click.echo("6. Sync Databases")
    click.echo("7. Export/Import Data")
    click.echo("8. MFA Settings")
    click.echo("9. Account Settings")
    click.echo("10. Logout")

def print_export_import_menu():
    """Print the export/import menu options"""
    click.echo("\n" + Fore.CYAN + "Export/Import Menu:" + Style.RESET_ALL)
    click.echo("1. Export to JSON (Encrypted)")
    click.echo("2. Export to JSON (Unencrypted)")
    click.echo("3. Export to CSV")
    click.echo("4. Import from JSON")
    click.echo("5. Import from CSV")
    click.echo("6. Back to Main Menu")

def print_mfa_menu(mfa_enabled):
    """Print the MFA settings menu options"""
    click.echo("\n" + Fore.CYAN + "MFA Settings:" + Style.RESET_ALL)
    if mfa_enabled:
        click.echo("1. Disable MFA")
        click.echo("2. Generate New Backup Codes")
    else:
        click.echo("1. Enable MFA")
    click.echo("3. Back to Main Menu")

def print_account_settings_menu():
    """Print the account settings menu options"""
    click.echo("\n" + Fore.CYAN + "Account Settings:" + Style.RESET_ALL)
    click.echo("1. Change Password")
    click.echo("2. View Account Information")
    click.echo("3. Back to Main Menu")

@click.group()
@click.pass_context
def cli(ctx):
    """Data Privacy Vault CLI"""
    ctx.ensure_object(dict)
    try:
        ctx.obj['engine'] = init_db()
        Session = sessionmaker(bind=ctx.obj['engine'])
        ctx.obj['session'] = Session()
        logger.info("Database initialized successfully")
    except Exception as e:
        click.echo(Fore.RED + f"Failed to initialize database: {str(e)}" + Style.RESET_ALL)
        logger.critical(f"Database initialization failed: {str(e)}")
        sys.exit(1)

@cli.command()
@click.option('--username', prompt=True, help='Your username')
@click.option('--email', prompt=True, help='Your email address')
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True, help='Your password')
@click.pass_context
@safe_db_operation
def register(ctx, username, email, password):
    """Register a new user account"""
    if not username or len(username) < 3:
        click.echo(Fore.RED + 'Username must be at least 3 characters long.' + Style.RESET_ALL)
        return

    # Validate email format
    if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
        click.echo(Fore.RED + 'Invalid email format.' + Style.RESET_ALL)
        return

    # Validate password strength
    is_valid, message = PasswordValidator.validate_password(password)
    if not is_valid:
        click.echo(Fore.RED + message + Style.RESET_ALL)
        return
    
    try:
        session = ctx.obj['session']
        
        # Check if username or email already exists
        existing_user = session.query(User).filter(
            (User.username == username) | (User.email == email)
        ).first()
        
        if existing_user:
            if existing_user.username == username:
                click.echo(Fore.RED + 'Username already exists. Please choose a different username.' + Style.RESET_ALL)
            else:
                click.echo(Fore.RED + 'Email already exists. Please use a different email.' + Style.RESET_ALL)
            return
        
        # Create new user
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        
        # Generate encryption key
        encryption_key = generate_key()[0]
        new_user.encryption_key = encryption_key
        
        session.add(new_user)
        session.commit()
        
        # Log the registration
        log_entry = AuditLog(
            user_id=new_user.id,
            action="register",
            details="New user registration"
        )
        session.add(log_entry)
        session.commit()
        
        click.echo(Fore.GREEN + 'User registered successfully!' + Style.RESET_ALL)
        logger.info(f"New user registered: {username}")
        
    except IntegrityError:
        session.rollback()
        click.echo(Fore.RED + 'Username or email already exists. Please choose different credentials.' + Style.RESET_ALL)
        logger.warning(f"Registration failed - duplicate username/email: {username}/{email}")
    except Exception as e:
        session.rollback()
        click.echo(Fore.RED + f'An unexpected error occurred: {str(e)}' + Style.RESET_ALL)
        logger.error(f"Registration error: {str(e)}")
        sys.exit(1)

@cli.command()
@click.option('--username', prompt=True, help='Your username')
@click.option('--password', prompt=True, hide_input=True, help='Your password')
@click.option('--mfa-code', prompt=False, help='Your MFA code if enabled')
@click.pass_context
def login(ctx, username, password, mfa_code):
    """Login to your account"""
    try:
        session = ctx.obj['session']
        user = session.query(User).filter_by(username=username).first()

        if not user:
            click.echo(Fore.RED + 'Invalid username or password. Please try again.' + Style.RESET_ALL)
            return
        
        # Check if account is locked
        if user.failed_login_attempts >= 5:
            click.echo(Fore.RED + 'Account is locked due to too many failed login attempts. Please try again later.' + Style.RESET_ALL)
            logger.warning(f"Login attempt on locked account: {username}")
            return
        
        # Verify password
        if user.check_password(password):
            # Check MFA if enabled
            if user.mfa_enabled:
                if not mfa_code:
                    mfa_code = click.prompt('Enter your MFA code', type=str)
                
                mfa_manager = MFAManager(user.mfa_secret)
                if not mfa_manager.verify_code(mfa_code):
                    user.increment_failed_login_attempts()
                    session.commit()
                    click.echo(Fore.RED + 'Invalid MFA code. Please try again.' + Style.RESET_ALL)
                    logger.warning(f"Failed MFA validation for user: {username}")
                    return
            
            # Reset failed login attempts and update last login
            user.reset_failed_login_attempts()
            session.commit()
            
            # Log successful login
            log_entry = AuditLog(
                user_id=user.id,
                action="login",
                details="Successful login"
            )
            session.add(log_entry)
            session.commit()
            
            click.echo(Fore.GREEN + f'Logged in as {username}' + Style.RESET_ALL)
            logger.info(f"User logged in: {username}")
            
            ctx.obj['user'] = user

            # Initialize DatabaseSynchronizer
            remote_url = os.getenv('REMOTE_DB_URL', 'http://example.com/api')
            api_key = os.getenv('API_KEY', 'your-api-key')
            ctx.obj['syncer'] = DatabaseSynchronizer(session, remote_url, api_key)

            # Perform initial sync
            click.echo(Fore.CYAN + "Syncing with remote database..." + Style.RESET_ALL)
            sync_result = ctx.obj['syncer'].perform_full_sync(user)
            if sync_result:
                click.echo(Fore.GREEN + "Sync completed successfully." + Style.RESET_ALL)
            else:
                click.echo(Fore.YELLOW + "Sync with remote server failed. Working in offline mode." + Style.RESET_ALL)

            # Main application loop
            while True:
                print_menu()
                option = click.prompt("\nSelect an option", type=click.Choice(['1', '2', '3', '4', '5', '6', '7', '8', '9', '10']))

                if option == '1':
                    view_credentials(ctx)
                elif option == '2':
                    add_credential(ctx)
                elif option == '3':
                    update_credential(ctx)
                elif option == '4':
                    delete_credential(ctx)
                elif option == '5':
                    generate_password(ctx)
                elif option == '6':
                    sync_databases(ctx)
                elif option == '7':
                    export_import_menu(ctx)
                elif option == '8':
                    mfa_settings(ctx)
                elif option == '9':
                    account_settings(ctx)
                elif option == '10':
                    click.echo(Fore.CYAN + "\nGoodbye!" + Style.RESET_ALL)
                    log_entry = AuditLog(
                        user_id=user.id,
                        action="logout",
                        details="User logged out"
                    )
                    session.add(log_entry)
                    session.commit()
                    logger.info(f"User logged out: {username}")
                    break
        else:
            # Increment failed login attempts
            user.increment_failed_login_attempts()
            session.commit()
            
            # Log failed login
            log_entry = AuditLog(
                user_id=user.id,
                action="login_failed",
                details="Failed login attempt"
            )
            session.add(log_entry)
            session.commit()
            
            click.echo(Fore.RED + 'Invalid username or password. Please try again.' + Style.RESET_ALL)
            logger.warning(f"Failed login attempt for user: {username}")
            
    except Exception as e:
        click.echo(Fore.RED + f'Error: {str(e)}' + Style.RESET_ALL)
        logger.error(f"Login error: {str(e)}")

@safe_db_operation
def sync_databases(ctx):
    """Sync credentials with the remote database"""
    click.echo(Fore.CYAN + "Syncing with remote database..." + Style.RESET_ALL)
    sync_result = ctx.obj['syncer'].perform_full_sync(ctx.obj['user'])
    if sync_result:
        click.echo(Fore.GREEN + "Sync completed successfully." + Style.RESET_ALL)
    else:
        click.echo(Fore.YELLOW + "Sync with remote server failed. Try again later." + Style.RESET_ALL)

@safe_db_operation
def view_credentials(ctx):
    """View all stored credentials"""
    user = ctx.obj['user']
    credentials = ctx.obj['session'].query(Credential).filter_by(user_id=user.id).all()
    
    if not credentials:
        click.echo(Fore.YELLOW + 'No credentials found.' + Style.RESET_ALL)
        return
    
    # Group credentials by category
    credentials_by_category = {}
    for credential in credentials:
        category = credential.category or 'Uncategorized'
        if category not in credentials_by_category:
            credentials_by_category[category] = []
        credentials_by_category[category].append(credential)
    
    click.echo(Fore.CYAN + '\nYour credentials:' + Style.RESET_ALL)
    
    for category, creds in sorted(credentials_by_category.items()):
        click.echo(f"\n{Fore.CYAN}{category}:{Style.RESET_ALL}")
        for credential in creds:
            star = "★ " if credential.favorite else ""
            decrypted_data = decrypt_data(credential.encrypted_data.encode(), user.encryption_key)
            url_info = f" ({credential.url})" if credential.url else ""
            click.echo(f"{star}{Fore.GREEN}{credential.id}.{Style.RESET_ALL} {credential.name}{url_info}: {decrypted_data}")

@safe_db_operation
def add_credential(ctx):
    """Add a new credential"""
    user = ctx.obj['user']
    name = click.prompt(Fore.CYAN + "Enter service name" + Style.RESET_ALL)
    if not name or len(name) < 1:
        click.echo(Fore.RED + 'Service name cannot be empty.' + Style.RESET_ALL)
        return
    
    # Check if credential with this name already exists
    existing = ctx.obj['session'].query(Credential).filter_by(name=name, user_id=user.id).first()
    if existing:
        overwrite = click.confirm(f"Credential '{name}' already exists. Do you want to overwrite it?")
        if not overwrite:
            click.echo(Fore.YELLOW + 'Operation cancelled.' + Style.RESET_ALL)
            return
        # Delete existing credential if overwriting
        ctx.obj['session'].delete(existing)
        ctx.obj['session'].commit()
    
    data = getpass(Fore.CYAN + "Enter data (password/key)" + Style.RESET_ALL)
    if not data:
        click.echo(Fore.RED + 'Credential data cannot be empty.' + Style.RESET_ALL)
        return
    
    category = click.prompt(Fore.CYAN + "Enter category (optional)" + Style.RESET_ALL, default='')
    url = click.prompt(Fore.CYAN + "Enter URL (optional)" + Style.RESET_ALL, default='')
    notes = click.prompt(Fore.CYAN + "Enter notes (optional)" + Style.RESET_ALL, default='')
    favorite = click.confirm(Fore.CYAN + "Mark as favorite?" + Style.RESET_ALL, default=False)
    
    try:
        encrypted_data = encrypt_data(data, user.encryption_key)
        new_credential = Credential(
            name=name, 
            encrypted_data=encrypted_data, 
            user_id=user.id,
            category=category if category else None,
            url=url if url else None,
            notes=notes if notes else None,
            favorite=favorite
        )
        ctx.obj['session'].add(new_credential)
        ctx.obj['session'].commit()
        
        # Log the action
        log_entry = AuditLog(
            user_id=user.id,
            action="add_credential",
            details=f"Added credential: {name}"
        )
        ctx.obj['session'].add(log_entry)
        ctx.obj['session'].commit()
        
        click.echo(Fore.GREEN + 'Credential added successfully!' + Style.RESET_ALL)
        
        # Sync to remote
        ctx.obj['syncer'].sync_to_remote(user)
        
    except Exception as e:
        ctx.obj['session'].rollback()
        click.echo(Fore.RED + f'An error occurred while adding the credential: {str(e)}' + Style.RESET_ALL)
        logger.error(f"Error adding credential: {str(e)}")

@safe_db_operation
def update_credential(ctx):
    """Update an existing credential"""
    view_credentials(ctx)
    credential_id = click.prompt(Fore.CYAN + "Enter the ID of the credential to update" + Style.RESET_ALL, type=int)
    
    credential = ctx.obj['session'].query(Credential).filter_by(id=credential_id, user_id=ctx.obj['user'].id).first()
    if not credential:
        click.echo(Fore.RED + 'Credential not found.' + Style.RESET_ALL)
        return
    
    # Display current values
    click.echo(Fore.CYAN + "\nCurrent values:" + Style.RESET_ALL)
    click.echo(f"Name: {credential.name}")
    click.echo(f"Category: {credential.category or 'None'}")
    click.echo(f"URL: {credential.url or 'None'}")
    click.echo(f"Favorite: {'Yes' if credential.favorite else 'No'}")
    click.echo(f"Notes: {credential.notes or 'None'}")
    
    # Get updated values
    update_data = click.confirm(Fore.CYAN + "Update credential data/password?" + Style.RESET_ALL, default=False)
    new_data = None
    if update_data:
        new_data = getpass(Fore.CYAN + "Enter new data" + Style.RESET_ALL)
        if not new_data:
            click.echo(Fore.RED + 'Credential data cannot be empty.' + Style.RESET_ALL)
            return
    
    name = click.prompt(Fore.CYAN + "Enter new name" + Style.RESET_ALL, default=credential.name)
    category = click.prompt(Fore.CYAN + "Enter new category" + Style.RESET_ALL, default=credential.category or '')
    url = click.prompt(Fore.CYAN + "Enter new URL" + Style.RESET_ALL, default=credential.url or '')
    notes = click.prompt(Fore.CYAN + "Enter new notes" + Style.RESET_ALL, default=credential.notes or '')
    favorite = click.confirm(Fore.CYAN + "Mark as favorite?" + Style.RESET_ALL, default=credential.favorite)
    
    try:
        if new_data:
            encrypted_data = encrypt_data(new_data, ctx.obj['user'].encryption_key)
            credential.encrypted_data = encrypted_data
        
        credential.name = name
        credential.category = category if category else None
        credential.url = url if url else None
        credential.notes = notes if notes else None
        credential.favorite = favorite
        
        ctx.obj['session'].commit()
        
        # Log the action
        log_entry = AuditLog(
            user_id=ctx.obj['user'].id,
            action="update_credential",
            details=f"Updated credential: {name}"
        )
        ctx.obj['session'].add(log_entry)
        ctx.obj['session'].commit()
        
        click.echo(Fore.GREEN + 'Credential updated successfully!' + Style.RESET_ALL)
        
        # Sync to remote
        ctx.obj['syncer'].sync_to_remote(ctx.obj['user'])
        
    except Exception as e:
        ctx.obj['session'].rollback()
        click.echo(Fore.RED + f'An error occurred while updating the credential: {str(e)}' + Style.RESET_ALL)
        logger.error(f"Error updating credential: {str(e)}")

@safe_db_operation
def delete_credential(ctx):
    """Delete an existing credential"""
    view_credentials(ctx)
    credential_id = click.prompt(Fore.CYAN + "Enter the ID of the credential to delete" + Style.RESET_ALL, type=int)
    
    credential = ctx.obj['session'].query(Credential).filter_by(id=credential_id, user_id=ctx.obj['user'].id).first()
    if not credential:
        click.echo(Fore.RED + 'Credential not found.' + Style.RESET_ALL)
        return
    
    confirm = click.confirm(Fore.YELLOW + f"Are you sure you want to delete '{credential.name}'?" + Style.RESET_ALL)
    if not confirm:
        click.echo(Fore.CYAN + 'Deletion cancelled.' + Style.RESET_ALL)
        return
    
    try:
        credential_name = credential.name
        ctx.obj['session'].delete(credential)
        
        # Log the action
        log_entry = AuditLog(
            user_id=ctx.obj['user'].id,
            action="delete_credential",
            details=f"Deleted credential: {credential_name}"
        )
        ctx.obj['session'].add(log_entry)
        ctx.obj['session'].commit()
        
        click.echo(Fore.GREEN + 'Credential deleted successfully!' + Style.RESET_ALL)
        
        # Sync to remote
        ctx.obj['syncer'].sync_to_remote(ctx.obj['user'])
        
    except Exception as e:
        ctx.obj['session'].rollback()
        click.echo(Fore.RED + f'An error occurred while deleting the credential: {str(e)}' + Style.RESET_ALL)
        logger.error(f"Error deleting credential: {str(e)}")

@cli.command()
@click.option('--length', default=16, help='Password length')
@click.option('--no-uppercase', is_flag=True, help='Exclude uppercase letters')
@click.option('--no-lowercase', is_flag=True, help='Exclude lowercase letters')
@click.option('--no-digits', is_flag=True, help='Exclude digits')
@click.option('--no-symbols', is_flag=True, help='Exclude symbols')
@click.pass_context
def generate_password(ctx, length=16, no_uppercase=False, no_lowercase=False, no_digits=False, no_symbols=False):
    """Generate a strong random password"""
    # Ensure at least one character type is included
    if no_uppercase and no_lowercase and no_digits and no_symbols:
        click.echo(Fore.RED + "Error: At least one character type must be included." + Style.RESET_ALL)
        return
    
    password = PasswordValidator.generate_password(
        length=length,
        include_uppercase=not no_uppercase,
        include_lowercase=not no_lowercase,
        include_digits=not no_digits,
        include_symbols=not no_symbols
    )
    
    click.echo(Fore.GREEN + f"Generated strong password: {password}" + Style.RESET_ALL)
    click.echo(Fore.YELLOW + "Make sure to save this password securely!" + Style.RESET_ALL)
    
    # Ask if user wants to copy to clipboard
    if click.confirm(Fore.CYAN + "Copy password to clipboard?" + Style.RESET_ALL):
        try:
            import pyperclip
            pyperclip.copy(password)
            click.echo(Fore.GREEN + "Password copied to clipboard!" + Style.RESET_ALL)
        except ImportError:
            click.echo(Fore.YELLOW + "Clipboard functionality not available. Install 'pyperclip' package." + Style.RESET_ALL)

@safe_db_operation
def export_import_menu(ctx):
    """Show export/import menu and handle options"""
    while True:
        print_export_import_menu()
        option = click.prompt("Select an option", type=click.Choice(['1', '2', '3', '4', '5', '6']))
        
        if option == '1':  # Export to JSON (Encrypted)
            export_to_json(ctx, encrypt=True)
        elif option == '2':  # Export to JSON (Unencrypted)
            export_to_json(ctx, encrypt=False)
        elif option == '3':  # Export to CSV
            export_to_csv(ctx)
        elif option == '4':  # Import from JSON
            import_from_json(ctx)
        elif option == '5':  # Import from CSV
            import_from_csv(ctx)
        elif option == '6':  # Back to Main Menu
            break

@safe_db_operation
def export_to_json(ctx, encrypt=True):
    """Export credentials to JSON file"""
    user = ctx.obj['user']
    
    output_path = click.prompt(
        Fore.CYAN + "Enter output file path" + Style.RESET_ALL,
        default=f"data_vault_export_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    )
    
    # Create DataPortabilityManager
    data_manager = DataPortabilityManager(ctx.obj['session'], user, user.encryption_key)
    
    # Export data
    success, message = data_manager.export_to_json(output_path, encrypt_export=encrypt)
    
    if success:
        click.echo(Fore.GREEN + message + Style.RESET_ALL)
        
        # Log the action
        log_entry = AuditLog(
            user_id=user.id,
            action="export_data",
            details=f"Exported credentials to JSON ({output_path})"
        )
        ctx.obj['session'].add(log_entry)
        ctx.obj['session'].commit()
    else:
        click.echo(Fore.RED + message + Style.RESET_ALL)

@safe_db_operation
def export_to_csv(ctx):
    """Export credentials to CSV file"""
    user = ctx.obj['user']
    
    output_path = click.prompt(
        Fore.CYAN + "Enter output file path" + Style.RESET_ALL,
        default=f"data_vault_export_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    )
    
    # Create DataPortabilityManager
    data_manager = DataPortabilityManager(ctx.obj['session'], user, user.encryption_key)
    
    # Export data
    success, message = data_manager.export_to_csv(output_path)
    
    if success:
        click.echo(Fore.GREEN + message + Style.RESET_ALL)
        click.echo(Fore.YELLOW + "Warning: CSV export contains unencrypted credentials!" + Style.RESET_ALL)
        
        # Log the action
        log_entry = AuditLog(
            user_id=user.id,
            action="export_data",
            details=f"Exported credentials to CSV ({output_path})"
        )
        ctx.obj['session'].add(log_entry)
        ctx.obj['session'].commit()
    else:
        click.echo(Fore.RED + message + Style.RESET_ALL)

@safe_db_operation
def import_from_json(ctx):
    """Import credentials from JSON file"""
    user = ctx.obj['user']
    
    input_path = click.prompt(Fore.CYAN + "Enter input file path" + Style.RESET_ALL)
    if not os.path.exists(input_path):
        click.echo(Fore.RED + f"File not found: {input_path}" + Style.RESET_ALL)
        return
    
    is_encrypted = click.confirm(Fore.CYAN + "Is the file encrypted?" + Style.RESET_ALL, default=True)
    replace_existing = click.confirm(Fore.CYAN + "Replace existing credentials?" + Style.RESET_ALL, default=False)
    
    # Create DataPortabilityManager
    data_manager = DataPortabilityManager(ctx.obj['session'], user, user.encryption_key)
    
    # Import data
    success, message = data_manager.import_from_json(input_path, is_encrypted, replace_existing)
    
    if success:
        click.echo(Fore.GREEN + message + Style.RESET_ALL)
        
        # Log the action
        log_entry = AuditLog(
            user_id=user.id,
            action="import_data",
            details=f"Imported credentials from JSON ({input_path})"
        )
        ctx.obj['session'].add(log_entry)
        ctx.obj['session'].commit()
        
        # Sync to remote
        ctx.obj['syncer'].sync_to_remote(user)
    else:
        click.echo(Fore.RED + message + Style.RESET_ALL)

@safe_db_operation
def import_from_csv(ctx):
    """Import credentials from CSV file"""
    user = ctx.obj['user']
    
    input_path = click.prompt(Fore.CYAN + "Enter input file path" + Style.RESET_ALL)
    if not os.path.exists(input_path):
        click.echo(Fore.RED + f"File not found: {input_path}" + Style.RESET_ALL)
        return
    
    replace_existing = click.confirm(Fore.CYAN + "Replace existing credentials?" + Style.RESET_ALL, default=False)
    
    # Create DataPortabilityManager
    data_manager = DataPortabilityManager(ctx.obj['session'], user, user.encryption_key)
    
    # Import data
    success, message = data_manager.import_from_csv(input_path, replace_existing)
    
    if success:
        click.echo(Fore.GREEN + message + Style.RESET_ALL)
        
        # Log the action
        log_entry = AuditLog(
            user_id=user.id,
            action="import_data",
            details=f"Imported credentials from CSV ({input_path})"
        )
        ctx.obj['session'].add(log_entry)
        ctx.obj['session'].commit()
        
        # Sync to remote
        ctx.obj['syncer'].sync_to_remote(user)
    else:
        click.echo(Fore.RED + message + Style.RESET_ALL)

@safe_db_operation
def mfa_settings(ctx):
    """Manage MFA settings"""
    user = ctx.obj['user']
    
    while True:
        print_mfa_menu(user.mfa_enabled)
        
        if user.mfa_enabled:
            option = click.prompt("Select an option", type=click.Choice(['1', '2', '3']))
            
            if option == '1':  # Disable MFA
                disable_mfa(ctx)
            elif option == '2':  # Generate New Backup Codes
                generate_backup_codes(ctx)
            elif option == '3':  # Back to Main Menu
                break
        else:
            option = click.prompt("Select an option", type=click.Choice(['1', '3']))
            
            if option == '1':  # Enable MFA
                enable_mfa(ctx)
            elif option == '3':  # Back to Main Menu
                break

@safe_db_operation
def enable_mfa(ctx):
    """Enable MFA for the current user"""
    user = ctx.obj['user']
    
    if user.mfa_enabled:
        click.echo(Fore.YELLOW + "MFA is already enabled." + Style.RESET_ALL)
        return
    
    # Generate MFA secret
    mfa_manager = MFAManager()
    
    # Display QR code instructions
    click.echo(Fore.CYAN + "\nMFA Setup Instructions:" + Style.RESET_ALL)
    click.echo("1. Install a TOTP app like Google Authenticator or Authy on your mobile device.")
    click.echo("2. In the app, add a new account by scanning the QR code or entering the secret key.")
    click.echo("3. Enter the code from the app to verify setup.")
    
    # Display secret key
    click.echo(Fore.GREEN + f"\nSecret key: {mfa_manager.secret_key}" + Style.RESET_ALL)
    click.echo("If you can't scan the QR code, manually enter this secret key in your TOTP app.")
    
    # Get QR code URI
    uri = mfa_manager.get_provisioning_uri(user.username)
    click.echo(Fore.YELLOW + f"\nQR code URI: {uri}" + Style.RESET_ALL)
    click.echo("You can generate a QR code using this URI with an online QR code generator.")
    
    # Verify MFA setup
    verification_code = click.prompt(Fore.CYAN + "\nEnter the verification code from your TOTP app" + Style.RESET_ALL)
    
    if mfa_manager.verify_code(verification_code):
        # Generate backup codes
        backup_codes = mfa_manager.generate_backup_codes()
        
        # Save MFA configuration
        user.mfa_secret = mfa_manager.secret_key
        user.mfa_enabled = True
        ctx.obj['session'].commit()
        
        # Log the action
        log_entry = AuditLog(
            user_id=user.id,
            action="enable_mfa",
            details="MFA enabled"
        )
        ctx.obj['session'].add(log_entry)
        ctx.obj['session'].commit()
        
        click.echo(Fore.GREEN + "MFA enabled successfully!" + Style.RESET_ALL)
        
        # Display backup codes
        click.echo(Fore.YELLOW + "\nBackup Codes (save these in a secure location):" + Style.RESET_ALL)
        for code in backup_codes:
            click.echo(Fore.GREEN + code + Style.RESET_ALL)
    else:
        click.echo(Fore.RED + "Verification failed. MFA not enabled." + Style.RESET_ALL)

@safe_db_operation
def disable_mfa(ctx):
    """Disable MFA for the current user"""
    user = ctx.obj['user']
    
    if not user.mfa_enabled:
        click.echo(Fore.YELLOW + "MFA is not enabled." + Style.RESET_ALL)
        return
    
    # Require verification
    verification_code = click.prompt(Fore.CYAN + "Enter your MFA code to confirm" + Style.RESET_ALL)
    
    mfa_manager = MFAManager(user.mfa_secret)
    if mfa_manager.verify_code(verification_code):
        # Disable MFA
        user.mfa_secret = None
        user.mfa_enabled = False
        ctx.obj['session'].commit()
        
        # Log the action
        log_entry = AuditLog(
            user_id=user.id,
            action="disable_mfa",
            details="MFA disabled"
        )
        ctx.obj['session'].add(log_entry)
        ctx.obj['session'].commit()
        
        click.echo(Fore.GREEN + "MFA disabled successfully." + Style.RESET_ALL)
    else:
        click.echo(Fore.RED + "Verification failed. MFA not disabled." + Style.RESET_ALL)

@safe_db_operation
def generate_backup_codes(ctx):
    """Generate new backup codes for MFA"""
    user = ctx.obj['user']
    
    if not user.mfa_enabled:
        click.echo(Fore.YELLOW + "MFA is not enabled." + Style.RESET_ALL)
        return
    
    # Require verification
    verification_code = click.prompt(Fore.CYAN + "Enter your MFA code to confirm" + Style.RESET_ALL)
    
    mfa_manager = MFAManager(user.mfa_secret)
    if mfa_manager.verify_code(verification_code):
        # Generate new backup codes
        backup_codes = mfa_manager.generate_backup_codes()
        
        # Log the action
        log_entry = AuditLog(
            user_id=user.id,
            action="generate_backup_codes",
            details="Generated new MFA backup codes"
        )
        ctx.obj['session'].add(log_entry)
        ctx.obj['session'].commit()
        
        # Display backup codes
        click.echo(Fore.YELLOW + "\nNew Backup Codes (save these in a secure location):" + Style.RESET_ALL)
        for code in backup_codes:
            click.echo(Fore.GREEN + code + Style.RESET_ALL)
    else:
        click.echo(Fore.RED + "Verification failed. Backup codes not generated." + Style.RESET_ALL)

@safe_db_operation
def account_settings(ctx):
    """Manage account settings"""
    while True:
        print_account_settings_menu()
        option = click.prompt("Select an option", type=click.Choice(['1', '2', '3']))
        
        if option == '1':  # Change Password
            change_password(ctx)
        elif option == '2':  # View Account Information
            view_account_info(ctx)
        elif option == '3':  # Back to Main Menu
            break

@safe_db_operation
def change_password(ctx):
    """Change user password"""
    user = ctx.obj['user']
    
    # Verify current password
    current_password = getpass(Fore.CYAN + "Enter current password" + Style.RESET_ALL)
    if not user.check_password(current_password):
        click.echo(Fore.RED + "Incorrect password." + Style.RESET_ALL)
        return
    
    # Get new password
    new_password = getpass(Fore.CYAN + "Enter new password" + Style.RESET_ALL)
    confirm_password = getpass(Fore.CYAN + "Confirm new password" + Style.RESET_ALL)
    
    if new_password != confirm_password:
        click.echo(Fore.RED + "Passwords do not match." + Style.RESET_ALL)
        return
    
    # Validate password strength
    is_valid, message = PasswordValidator.validate_password(new_password)
    if not is_valid:
        click.echo(Fore.RED + message + Style.RESET_ALL)
        return
    
    # Update password
    user.set_password(new_password)
    ctx.obj['session'].commit()
    
    # Log the action
    log_entry = AuditLog(
        user_id=user.id,
        action="change_password",
        details="Password changed"
    )
    ctx.obj['session'].add(log_entry)
    ctx.obj['session'].commit()
    
    click.echo(Fore.GREEN + "Password changed successfully!" + Style.RESET_ALL)

@safe_db_operation
def view_account_info(ctx):
    """View account information"""
    user = ctx.obj['user']
    
    # Count credentials
    credential_count = ctx.obj['session'].query(Credential).filter_by(user_id=user.id).count()
    
    # Get last login time
    last_login = user.last_login.strftime("%Y-%m-%d %H:%M:%S") if user.last_login else "Unknown"
    
    # Get account creation time
    creation_date = user.created_at.strftime("%Y-%m-%d %H:%M:%S") if user.created_at else "Unknown"
    
    # Display account information
    click.echo(Fore.CYAN + "\nAccount Information:" + Style.RESET_ALL)
    click.echo(f"Username: {user.username}")
    click.echo(f"Email: {user.email}")
    click.echo(f"Account created: {creation_date}")
    click.echo(f"Last login: {last_login}")
    click.echo(f"MFA enabled: {'Yes' if user.mfa_enabled else 'No'}")
    click.echo(f"Stored credentials: {credential_count}")

if __name__ == '__main__':
    cli()



