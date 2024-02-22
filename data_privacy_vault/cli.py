
import click
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.orm import sessionmaker
from getpass import getpass
from data_privacy_vault.models import User, Credential, Base
from sqlalchemy.exc import IntegrityError
from data_privacy_vault.encription import hash_password, verify_password
from colorama import Fore, Style


def validate_username(ctx, param, value):
    if not value or not value.strip():
        raise click.BadParameter('Username cannot be empty.')
    return value

def validate_password(ctx, param, value):
    if not value or not value.strip():
        raise click.BadParameter('Password cannot be empty.')
    return value

def validate_service_name(value):
    if not value or not value.strip():
        raise click.BadParameter('Service name cannot be empty.')
    return value

def validate_data(value):
    if not value or not value.strip():
        raise click.BadParameter('Data cannot be empty.')
    return value

def add_credential(ctx, name, data):
    try:
        if 'user' not in ctx.obj:
            raise click.ClickException(Fore.RED + 'Please login first!' + Style.RESET_ALL)

        session = ctx.obj['session']
        new_credential = Credential(name=name, data=data, user_id=ctx.obj['user'].id)
        session.add(new_credential)
        session.commit()
        click.echo(Fore.GREEN + 'Credential added successfully!' + Style.RESET_ALL)
    except Exception as e:
        click.echo(Fore.RED + f'Error: {str(e)}' + Style.RESET_ALL)

def view_credentials(ctx):
    try:
        if 'user' not in ctx.obj:
            raise click.ClickException(Fore.RED + 'Please login first!' + Style.RESET_ALL)

        session = ctx.obj['session']
        user_credentials = session.query(Credential).filter_by(user_id=ctx.obj['user'].id).all()

        if user_credentials:
            click.echo(Fore.CYAN + 'Your credentials:' + Style.RESET_ALL)
            for credential in user_credentials:
                click.echo(f'{credential.name}: {credential.data}')
        else:
            click.echo(Fore.YELLOW + 'No credentials found.' + Style.RESET_ALL)
    except Exception as e:
        click.echo(Fore.RED + f'Error: {str(e)}' + Style.RESET_ALL)

@click.group()
@click.pass_context
def cli(ctx):
    try:
        ctx.ensure_object(dict)
        ctx.obj['engine'] = create_engine('sqlite:///data_vault.db')
        Base.metadata.create_all(ctx.obj['engine'])
        Session = sessionmaker(bind=ctx.obj['engine'])
        ctx.obj['session'] = Session()
    except Exception as e:
        click.echo(Fore.RED + f'Error: {str(e)}' + Style.RESET_ALL)

@cli.command()
@click.option('--username', prompt=True, help='Your username', callback=validate_username)
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True, help='Your password', callback=validate_password)
@click.pass_context
def register(ctx, username, password):
    try:
        hashed_password = hash_password(password)
        session = ctx.obj['session']
        new_user = User(username=username, password=hashed_password)
        session.add(new_user)
        session.commit()
        click.echo(Fore.GREEN + 'User registered successfully!' + Style.RESET_ALL)
    except IntegrityError:
        click.echo(Fore.RED + 'Username already exists. Please choose a different username.' + Style.RESET_ALL)
    except Exception as e:
        click.echo(Fore.RED + f'Error: {str(e)}' + Style.RESET_ALL)

@cli.command()
@click.option('--username', prompt=True, help='Your username', callback=validate_username)
@click.option('--password', prompt=True, hide_input=True, help='Your password', callback=validate_password)
@click.pass_context
def login(ctx, username, password):
    try:
        session = ctx.obj['session']
        user = session.query(User).filter_by(username=username).first()

        if user and verify_password(password, user.password):
            click.echo(Fore.GREEN + f'Logged in as {username}' + Style.RESET_ALL)
            ctx.obj['user'] = user
            while True:
                click.echo("\nOptions:")
                click.echo("1. View Credentials")
                click.echo("2. Add Credential")
                click.echo("3. Logout")

                option = input("\nSelect an option: ")

                if option == '1':
                    view_credentials(ctx)
                elif option == '2':
                    service_name = click.prompt(Fore.CYAN + "Enter service name: " + Style.RESET_ALL, type=str, show_default=False, prompt_suffix="")
                    data = getpass(Fore.CYAN + "Enter data: " + Style.RESET_ALL)
                    add_credential(ctx, service_name, data)
                elif option == '3':
                    click.echo(Fore.CYAN + "\nGoodbye!" + Style.RESET_ALL)
                    break
                else:
                    click.echo(Fore.YELLOW + "Invalid option. Please try again." + Style.RESET_ALL)
        else:
            click.echo(Fore.RED + 'Invalid username or password. Please try again.' + Style.RESET_ALL)
    except Exception as e:
        click.echo(Fore.RED + f'Error: {str(e)}' + Style.RESET_ALL)

if __name__ == '__main__':
    cli(obj={})


