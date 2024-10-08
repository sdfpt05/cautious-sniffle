from setuptools import setup, find_packages

setup(
    name='data_vault',
    version='0.1',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'click',
        'flask',
        'flask-jwt-extended',
        'flask-migrate',
        'flask-limiter',
        'sqlalchemy',
        'cryptography',
        'python-dotenv',
    ],
    entry_points='''
        [console_scripts]
        data-vault-cli=data_vault_cli.cli:cli
    ''',
)