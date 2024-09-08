import click
from sqlalchemy.orm import sessionmaker
from getpass import getpass
from shared.models import User, Credential, init_db
from sqlalchemy.exc import IntegrityError
from shared.encryption import hash_password, verify_password, generate_key, encrypt_data, decrypt_data
from colorama import Fore, Style
import re
import sys
import secrets
import string

def validate_password_strength(password):
    if len(password) < 12:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True

def generate_strong_password(length=16):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

@click.group()
@click.pass_context
def cli(ctx):
    ctx.ensure_object(dict)
    ctx.obj['engine'] = init_db()
    Session = sessionmaker(bind=ctx.obj['engine'])
    ctx.obj['session'] = Session()

@cli.command()
@click.option('--username', prompt=True, help='Your username')
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True, help='Your password')
@click.pass_context
def register(ctx, username, password):
    if not username or len(username) < 3:
        click.echo(Fore.RED + 'Username must be at least 3 characters long.' + Style.RESET_ALL)
        return

    if not validate_password_strength(password):
        click.echo(Fore.RED + 'Password is too weak. It must be at least 12 characters long and contain uppercase, lowercase, numbers, and special characters.' + Style.RESET_ALL)
        return
    
    try:
        hashed_password, salt = hash_password(password)
        encryption_key = generate_key()
        session = ctx.obj['session']
        new_user = User(username=username, password=hashed_password, salt=salt, encryption_key=encryption_key)
        session.add(new_user)
        session.commit()
        click.echo(Fore.GREEN + 'User registered successfully!' + Style.RESET_ALL)
    except IntegrityError:
        click.echo(Fore.RED + 'Username already exists. Please choose a different username.' + Style.RESET_ALL)
    except Exception as e:
        click.echo(Fore.RED + f'An unexpected error occurred: {str(e)}' + Style.RESET_ALL)
        sys.exit(1)

def print_menu():
    click.echo("\n" + Fore.CYAN + "Options:" + Style.RESET_ALL)
    click.echo("1. View Credentials")
    click.echo("2. Add Credential")
    click.echo("3. Update Credential")
    click.echo("4. Delete Credential")
    click.echo("5. Generate Strong Password")
    click.echo("6. Logout")

@cli.command()
@click.option('--username', prompt=True, help='Your username')
@click.option('--password', prompt=True, hide_input=True, help='Your password')
@click.pass_context
def login(ctx, username, password):
    try:
        session = ctx.obj['session']
        user = session.query(User).filter_by(username=username).first()

        if user and verify_password(password, user.password, user.salt):
            click.echo(Fore.GREEN + f'Logged in as {username}' + Style.RESET_ALL)
            ctx.obj['user'] = user
            while True:
                print_menu()
                option = click.prompt("\nSelect an option", type=click.Choice(['1', '2', '3', '4', '5', '6']))

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
                    click.echo(Fore.CYAN + "\nGoodbye!" + Style.RESET_ALL)
                    break
        else:
            click.echo(Fore.RED + 'Invalid username or password. Please try again.' + Style.RESET_ALL)
    except Exception as e:
        click.echo(Fore.RED + f'Error: {str(e)}' + Style.RESET_ALL)

def view_credentials(ctx):
    user = ctx.obj['user']
    credentials = ctx.obj['session'].query(Credential).filter_by(user=user).all()
    if credentials:
        click.echo(Fore.CYAN + 'Your credentials:' + Style.RESET_ALL)
        for credential in credentials:
            decrypted_data = decrypt_data(credential.data, user.encryption_key)
            click.echo(f'{credential.id}. {credential.name}: {decrypted_data}')
    else:
        click.echo(Fore.YELLOW + 'No credentials found.' + Style.RESET_ALL)

def add_credential(ctx):
    user = ctx.obj['user']
    name = click.prompt(Fore.CYAN + "Enter service name" + Style.RESET_ALL)
    if not name or len(name) < 1:
        click.echo(Fore.RED + 'Service name cannot be empty.' + Style.RESET_ALL)
        return
    data = getpass(Fore.CYAN + "Enter data" + Style.RESET_ALL)
    if not data:
        click.echo(Fore.RED + 'Credential data cannot be empty.' + Style.RESET_ALL)
        return
    try:
        encrypted_data = encrypt_data(data, user.encryption_key)
        new_credential = Credential(name=name, data=encrypted_data, user=user)
        ctx.obj['session'].add(new_credential)
        ctx.obj['session'].commit()
        click.echo(Fore.GREEN + 'Credential added successfully!' + Style.RESET_ALL)
    except Exception as e:
        click.echo(Fore.RED + f'An error occurred while adding the credential: {str(e)}' + Style.RESET_ALL)

def update_credential(ctx):
    view_credentials(ctx)
    credential_id = click.prompt(Fore.CYAN + "Enter the ID of the credential to update" + Style.RESET_ALL, type=int)
    credential = ctx.obj['session'].query(Credential).filter_by(id=credential_id, user=ctx.obj['user']).first()
    if credential:
        new_data = getpass(Fore.CYAN + "Enter new data" + Style.RESET_ALL)
        if not new_data:
            click.echo(Fore.RED + 'Credential data cannot be empty.' + Style.RESET_ALL)
            return
        try:
            encrypted_data = encrypt_data(new_data, ctx.obj['user'].encryption_key)
            credential.data = encrypted_data
            ctx.obj['session'].commit()
            click.echo(Fore.GREEN + 'Credential updated successfully!' + Style.RESET_ALL)
        except Exception as e:
            click.echo(Fore.RED + f'An error occurred while updating the credential: {str(e)}' + Style.RESET_ALL)
    else:
        click.echo(Fore.RED + 'Credential not found.' + Style.RESET_ALL)

def delete_credential(ctx):
    view_credentials(ctx)
    credential_id = click.prompt(Fore.CYAN + "Enter the ID of the credential to delete" + Style.RESET_ALL, type=int)
    credential = ctx.obj['session'].query(Credential).filter_by(id=credential_id, user=ctx.obj['user']).first()
    if credential:
        confirm = click.confirm(Fore.YELLOW + "Are you sure you want to delete this credential?" + Style.RESET_ALL)
        if confirm:
            try:
                ctx.obj['session'].delete(credential)
                ctx.obj['session'].commit()
                click.echo(Fore.GREEN + 'Credential deleted successfully!' + Style.RESET_ALL)
            except Exception as e:
                click.echo(Fore.RED + f'An error occurred while deleting the credential: {str(e)}' + Style.RESET_ALL)
        else:
            click.echo(Fore.CYAN + 'Deletion cancelled.' + Style.RESET_ALL)
    else:
        click.echo(Fore.RED + 'Credential not found.' + Style.RESET_ALL)

@cli.command()
@click.pass_context
def generate_password(ctx):
    password = generate_strong_password()
    click.echo(Fore.GREEN + f"Generated strong password: {password}" + Style.RESET_ALL)
    click.echo(Fore.YELLOW + "Make sure to save this password securely!" + Style.RESET_ALL)

if __name__ == '__main__':
    cli(obj={})


