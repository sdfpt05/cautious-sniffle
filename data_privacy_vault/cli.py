import click
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.orm import sessionmaker
from getpass import getpass
from data_privacy_vault.models import User, Credential, Base
from data_privacy_vault.encription import hash_password, verify_password

def validate_username(ctx, param, value):
    if not value or not value.strip():
        raise click.BadParameter('Username cannot be empty.')
    return value

def validate_password(ctx, param, value):
    if not value or not value.strip():
        raise click.BadParameter('Password cannot be empty.')
    return value

def validate_service_name(ctx, param, value):
    if not value or not value.strip():
        raise click.BadParameter('Service name cannot be empty.')
    return value

def validate_data(ctx, param, value):
    if not value or not value.strip():
        raise click.BadParameter('Data cannot be empty.')
    return value

def add_credential(ctx, name, data):
    try:
        if 'user' not in ctx.obj:
            raise click.ClickException('Please login first!')

        session = ctx.obj['session']
        new_credential = Credential(name=name, data=data, user_id=ctx.obj['user'].id)
        session.add(new_credential)
        session.commit()
        click.echo('Credential added successfully!')
    except Exception as e:
        click.echo(f'Error: {str(e)}')

def view_credentials(ctx):
    try:
        if 'user' not in ctx.obj:
            raise click.ClickException('Please login first!')

        session = ctx.obj['session']
        user_credentials = session.query(Credential).filter_by(user_id=ctx.obj['user'].id).all()

        if user_credentials:
            click.echo('Your credentials:')
            for credential in user_credentials:
                click.echo(f'{credential.name}: {credential.data}')
        else:
            click.echo('No credentials found.')
    except Exception as e:
        click.echo(f'Error: {str(e)}')

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
        click.echo(f'Error: {str(e)}')

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
        click.echo('User registered successfully!')
    except IntegrityError:
        click.echo('Username already exists. Please choose a different username.')
    except Exception as e:
        click.echo(f'Error: {str(e)}')

@cli.command()
@click.option('--username', prompt=True, help='Your username', callback=validate_username)
@click.option('--password', prompt=True, hide_input=True, help='Your password', callback=validate_password)
@click.pass_context
def login(ctx, username, password):
    try:
        session = ctx.obj['session']
        user = session.query(User).filter_by(username=username).first()

        if user and verify_password(password, user.password):
            click.echo(f'Logged in as {username}')
            ctx.obj['user'] = user
            while True:
                click.echo("1. view_credentials")
                click.echo("2. add_credentials")
                click.echo("3. log_out")

                option = input("\nSelect an option: ")

                if option == '1':
                    user_credentials = session.query(Credential).filter_by(user_id=ctx.obj['user'].id).all()

                    if user_credentials:
                        click.echo('\nYour credentials:')
                        for credential in user_credentials:
                            click.echo(f'{credential.name}: {credential.data}')
                    else:
                        click.echo('\nNo credentials found.')
                elif option == '2':
                    service_name = click.prompt("\nEnter service name: ", callback=validate_service_name)
                    data = getpass("Enter data: ", callback=validate_data)
                    new_credential = Credential(name=service_name, data=data, user_id=ctx.obj['user'].id)
                    session.add(new_credential)
                    session.commit()
                    click.echo('\nCredential added successfully!')
                    return
                elif option == '3':
                    click.echo("\nGoodbye")
                    break
        else:
            click.echo('\nInvalid username or password. Please try again.')
    except Exception as e:
        click.echo(f'Error: {str(e)}')

if __name__ == '__main__':
    cli(obj={})
