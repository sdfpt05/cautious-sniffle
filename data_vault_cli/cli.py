import click
from sqlalchemy.orm import sessionmaker
from getpass import getpass
from data_privacy_vault.models import User, Credential, init_db
from sqlalchemy.exc import IntegrityError
from data_privacy_vault.encryption import hash_password, verify_password, generate_key, encrypt_data, decrypt_data
from colorama import Fore, Style
import re

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
        click.echo(Fore.RED + f'Error: {str(e)}' + Style.RESET_ALL)

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
                click.echo("\nOptions:")
                click.echo("1. View Credentials")
                click.echo("2. Add Credential")
                click.echo("3. Update Credential")
                click.echo("4. Delete Credential")
                click.echo("5. Logout")

                option = input("\nSelect an option: ")

                if option == '1':
                    view_credentials(ctx)
                elif option == '2':
                    add_credential(ctx)
                elif option == '3':
                    update_credential(ctx)
                elif option == '4':
                    delete_credential(ctx)
                elif option == '5':
                    click.echo(Fore.CYAN + "\nGoodbye!" + Style.RESET_ALL)
                    break
                else:
                    click.echo(Fore.YELLOW + "Invalid option. Please try again." + Style.RESET_ALL)
        else:
            click.echo(Fore.RED + 'Invalid username or password. Please try again.' + Style.RESET_ALL)
    except Exception as e:
        click.echo(Fore.RED + f'Error: {str(e)}' + Style.RESET_ALL)

def view_credentials(ctx):
    user = ctx.obj['user']
    if user.credentials:
        click.echo(Fore.CYAN + 'Your credentials:' + Style.RESET_ALL)
        for credential in user.credentials:
            click.echo(f'{credential.id}. {credential.name}: {credential.data}')
    else:
        click.echo(Fore.YELLOW + 'No credentials found.' + Style.RESET_ALL)

def add_credential(ctx):
    user = ctx.obj['user']
    name = click.prompt(Fore.CYAN + "Enter service name" + Style.RESET_ALL)
    data = getpass(Fore.CYAN + "Enter data" + Style.RESET_ALL)
    new_credential = Credential(name=name, data=data, user=user)
    ctx.obj['session'].add(new_credential)
    ctx.obj['session'].commit()
    click.echo(Fore.GREEN + 'Credential added successfully!' + Style.RESET_ALL)

def update_credential(ctx):
    view_credentials(ctx)
    credential_id = click.prompt(Fore.CYAN + "Enter the ID of the credential to update" + Style.RESET_ALL, type=int)
    credential = ctx.obj['session'].query(Credential).filter_by(id=credential_id, user=ctx.obj['user']).first()
    if credential:
        new_data = getpass(Fore.CYAN + "Enter new data" + Style.RESET_ALL)
        credential.data = new_data
        ctx.obj['session'].commit()
        click.echo(Fore.GREEN + 'Credential updated successfully!' + Style.RESET_ALL)
    else:
        click.echo(Fore.RED + 'Credential not found.' + Style.RESET_ALL)

def delete_credential(ctx):
    view_credentials(ctx)
    credential_id = click.prompt(Fore.CYAN + "Enter the ID of the credential to delete" + Style.RESET_ALL, type=int)
    credential = ctx.obj['session'].query(Credential).filter_by(id=credential_id, user=ctx.obj['user']).first()
    if credential:
        ctx.obj['session'].delete(credential)
        ctx.obj['session'].commit()
        click.echo(Fore.GREEN + 'Credential deleted successfully!' + Style.RESET_ALL)
    else:
        click.echo(Fore.RED + 'Credential not found.' + Style.RESET_ALL)

if __name__ == '__main__':
    cli(obj={})


