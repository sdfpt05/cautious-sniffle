import click
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from getpass import getpass
from data_privacy_vault.models import User, Credential, Base
from sqlalchemy.exc import IntegrityError
from data_privacy_vault.encryption import hash_password, verify_password, encrypt_data, decrypt_data
from colorama import Fore, Style
import os

def get_db_session():
    engine = create_engine(os.environ.get('DATABASE_URL', 'sqlite:///data_vault.db'))
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()

def validate_input(value, field_name):
    if not value or not value.strip():
        raise click.BadParameter(f'{field_name} cannot be empty.')
    return value.strip()

@click.group()
@click.pass_context
def cli(ctx):
    ctx.ensure_object(dict)
    ctx.obj['session'] = get_db_session()

@cli.command()
@click.option('--username', prompt=True, help='Your username', callback=lambda _, __, x: validate_input(x, 'Username'))
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True, help='Your password', callback=lambda _, __, x: validate_input(x, 'Password'))
@click.pass_context
def register(ctx, username, password):
    try:
        hashed_password = hash_password(password)
        new_user = User(username=username, password=hashed_password)
        ctx.obj['session'].add(new_user)
        ctx.obj['session'].commit()
        click.echo(Fore.GREEN + 'User registered successfully!' + Style.RESET_ALL)
    except IntegrityError:
        click.echo(Fore.RED + 'Username already exists. Please choose a different username.' + Style.RESET_ALL)
    except Exception as e:
        click.echo(Fore.RED + f'Error: {str(e)}' + Style.RESET_ALL)

@cli.command()
@click.option('--username', prompt=True, help='Your username', callback=lambda _, __, x: validate_input(x, 'Username'))
@click.option('--password', prompt=True, hide_input=True, help='Your password', callback=lambda _, __, x: validate_input(x, 'Password'))
@click.pass_context
def login(ctx, username, password):
    try:
        user = ctx.obj['session'].query(User).filter_by(username=username).first()
        if user and verify_password(password, user.password):
            ctx.obj['user'] = user
            click.echo(Fore.GREEN + f'Logged in as {username}' + Style.RESET_ALL)
            handle_logged_in_user(ctx)
        else:
            click.echo(Fore.RED + 'Invalid username or password. Please try again.' + Style.RESET_ALL)
    except Exception as e:
        click.echo(Fore.RED + f'Error: {str(e)}' + Style.RESET_ALL)

def handle_logged_in_user(ctx):
    while True:
        click.echo("\nOptions:")
        click.echo("1. View Credentials")
        click.echo("2. Add Credential")
        click.echo("3. Logout")

        option = click.prompt("Select an option", type=click.Choice(['1', '2', '3']))

        if option == '1':
            view_credentials(ctx)
        elif option == '2':
            add_credential(ctx)
        elif option == '3':
            click.echo(Fore.CYAN + "\nGoodbye!" + Style.RESET_ALL)
            break

def add_credential(ctx):
    name = click.prompt(Fore.CYAN + "Enter service name" + Style.RESET_ALL, type=str)
    data = getpass(Fore.CYAN + "Enter data" + Style.RESET_ALL)
    encrypted_data = encrypt_data(data)
    new_credential = Credential(name=name, data=encrypted_data, user_id=ctx.obj['user'].id)
    ctx.obj['session'].add(new_credential)
    ctx.obj['session'].commit()
    click.echo(Fore.GREEN + 'Credential added successfully!' + Style.RESET_ALL)

def view_credentials(ctx):
    user_credentials = ctx.obj['session'].query(Credential).filter_by(user_id=ctx.obj['user'].id).all()
    if user_credentials:
        click.echo(Fore.CYAN + 'Your credentials:' + Style.RESET_ALL)
        for credential in user_credentials:
            decrypted_data = decrypt_data(credential.data)
            click.echo(f'{credential.name}: {decrypted_data}')
    else:
        click.echo(Fore.YELLOW + 'No credentials found.' + Style.RESET_ALL)

if __name__ == '__main__':
    cli(obj={})


