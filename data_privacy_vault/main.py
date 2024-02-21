import click
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.orm import sessionmaker
from getpass import getpass
from models import User, Credential, Base

def add_credential(ctx, name, data):
    if 'user' not in ctx.obj:
        click.echo('Please login first!')
        return

    session = ctx.obj['session']
    new_credential = Credential(name=name, data=data, user_id=ctx.obj['user'].id)
    session.add(new_credential)
    session.commit()
    click.echo('Credential added successfully!')


def view_credentials(ctx):
    if 'user' not in ctx.obj:
        click.echo('Please login first!')
        return

    session = ctx.obj['session']
    user_credentials = session.query(Credential).filter_by(user_id=ctx.obj['user'].id).all()

    if user_credentials:
        click.echo('Your credentials:')
        for credential in user_credentials:
            click.echo(f'{credential.name}: {credential.data}')
    else:
        click.echo('No credentials found.')

@click.group()
@click.pass_context
def cli(ctx):
    ctx.ensure_object(dict)
    ctx.obj['engine'] = create_engine('sqlite:///data_vault.db')
    Base.metadata.create_all(ctx.obj['engine'])
    Session = sessionmaker(bind=ctx.obj['engine'])
    ctx.obj['session'] = Session()

@cli.command()
@click.option('--username', prompt=True, help='Your username')
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True, help='Your password')
@click.pass_context
def register(ctx, username, password):
    session = ctx.obj['session']
    new_user = User(username=username, password=password)
    session.add(new_user)
    session.commit()
    click.echo('User registered successfully!')

@cli.command()
@click.option('--username', prompt=True, help='Your username')
@click.option('--password', prompt=True, hide_input=True, help='Your password')
@click.pass_context
def login(ctx, username, password):
    session = ctx.obj['session']
    user = session.query(User).filter_by(username=username, password=password).first()

    if user:
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
                service_name = input("\nEnter service name: ")
                data = getpass("Enter data: ")
                new_credential = Credential(name = service_name, data=data, user_id=ctx.obj['user'].id)
                session.add(new_credential)
                session.commit()
                session.close()
                click.echo('\nCredential added successfully!')
                return
            elif option == '3':
                click.echo("\nGooodbye")
                break
    else:
        click.echo('\nInvalid username or password. Please try again.')

if __name__ == '__main__':
    cli(obj={})