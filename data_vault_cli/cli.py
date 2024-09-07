import click
from sqlalchemy.orm import sessionmaker
from models import User, Credential, init_db
from encryption import EncryptionManager, generate_key
import os
from dotenv import load_dotenv

load_dotenv()

DB_URL = os.getenv('DATABASE_URL', 'sqlite:///data_vault.db')
engine = init_db(DB_URL)
Session = sessionmaker(bind=engine)

encryption_key, _ = generate_key(os.getenv('ENCRYPTION_SECRET', 'default-secret'))
encryption_manager = EncryptionManager(encryption_key)

@click.group()
@click.pass_context
def cli(ctx):
    ctx.ensure_object(dict)
    ctx.obj['session'] = Session()

@cli.command()
@click.option('--username', prompt=True, help='Your username')
@click.option('--email', prompt=True, help='Your email')
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True, help='Your password')
@click.pass_context
def register(ctx, username, email, password):
    session = ctx.obj['session']
    if session.query(User).filter((User.username == username) | (User.email == email)).first():
        click.echo("Username or email already exists.")
        return
    new_user = User(username=username, email=email)
    new_user.set_password(password)
    session.add(new_user)
    session.commit()
    click.echo("User registered successfully.")

@cli.command()
@click.option('--username', prompt=True, help='Your username')
@click.option('--password', prompt=True, hide_input=True, help='Your password')
@click.pass_context
def login(ctx, username, password):
    session = ctx.obj['session']
    user = session.query(User).filter_by(username=username).first()
    if user and user.check_password(password):
        ctx.obj['user'] = user
        click.echo(f"Logged in as {username}")
        credential_menu(ctx)
    else:
        click.echo("Invalid username or password.")

def credential_menu(ctx):
    while True:
        choice = click.prompt(
            "Choose an action:\n1. View credentials\n2. Add credential\n3. Update credential\n4. Delete credential\n5. Logout",
            type=click.Choice(['1', '2', '3', '4', '5'])
        )
        if choice == '1':
            view_credentials(ctx)
        elif choice == '2':
            add_credential(ctx)
        elif choice == '3':
            update_credential(ctx)
        elif choice == '4':
            delete_credential(ctx)
        elif choice == '5':
            click.echo("Logged out.")
            break

def view_credentials(ctx):
    user = ctx.obj['user']
    for cred in user.credentials:
        decrypted_data = encryption_manager.decrypt_data(cred.encrypted_data.encode())
        click.echo(f"ID: {cred.id}, Name: {cred.name}, Data: {decrypted_data}")

def add_credential(ctx):
    name = click.prompt("Enter credential name")
    data = click.prompt("Enter credential data", hide_input=True)
    encrypted_data = encryption_manager.encrypt_data(data)
    new_cred = Credential(name=name, encrypted_data=encrypted_data, user_id=ctx.obj['user'].id)
    ctx.obj['session'].add(new_cred)
    ctx.obj['session'].commit()
    click.echo("Credential added successfully.")

def update_credential(ctx):
    cred_id = click.prompt("Enter credential ID to update", type=int)
    cred = ctx.obj['session'].query(Credential).filter_by(id=cred_id, user_id=ctx.obj['user'].id).first()
    if not cred:
        click.echo("Credential not found.")
        return
    name = click.prompt("Enter new name (leave blank to keep current)")
    data = click.prompt("Enter new data (leave blank to keep current)", hide_input=True)
    if name:
        cred.name = name
    if data:
        cred.encrypted_data = encryption_manager.encrypt_data(data)
    ctx.obj['session'].commit()
    click.echo("Credential updated successfully.")

def delete_credential(ctx):
    cred_id = click.prompt("Enter credential ID to delete", type=int)
    cred = ctx.obj['session'].query(Credential).filter_by(id=cred_id, user_id=ctx.obj['user'].id).first()
    if not cred:
        click.echo("Credential not found.")
        return
    ctx.obj['session'].delete(cred)
    ctx.obj['session'].commit()
    click.echo("Credential deleted successfully.")

if __name__ == '__main__':
    cli()


