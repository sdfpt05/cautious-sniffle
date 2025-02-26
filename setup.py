from setuptools import setup, find_packages
import os

# Read requirements
with open('requirements.txt') as f:
    requirements = f.read().splitlines()

# Filter out comments and empty lines
requirements = [line for line in requirements if line and not line.startswith('#')]

# Split dev requirements
dev_requirements = [line for line in requirements if 'pytest' in line or 'black' in line or 'flake8' in line]

# Get long description from README
with open('README.md', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='data_privacy_vault',
    version='1.0.0',
    description='A secure credential management system with CLI, web, and browser interfaces',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Your Name',
    author_email='your.email@example.com',
    url='https://github.com/yourusername/data-privacy-vault',
    packages=find_packages(exclude=['tests*']),
    include_package_data=True,
    python_requires='>=3.8',
    install_requires=[
        'click',
        'SQLAlchemy',
        'cryptography',
        'python-dotenv',
        'passlib',
        'argon2-cffi',
        'colorama',
        'pyotp',
        'qrcode',
        'requests',
        'Pillow',
        'pyperclip',
    ],
    extras_require={
        'web': [
            'Flask',
            'Flask-JWT-Extended',
            'Flask-Migrate',
            'Flask-SQLAlchemy',
            'Flask-Limiter',
            'Flask-WTF',
            'Flask-Cors',
            'Flask-Talisman',
            'gunicorn',
            'Werkzeug',
        ],
        'dev': dev_requirements,
    },
    entry_points={
        'console_scripts': [
            'data-vault-cli=data_vault_cli.run:main',
            'data-vault-web=data_vault_web.app:main',
            'data-vault-init=data_vault_cli.run:init_db',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: End Users/Desktop',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Security',
        'Topic :: Utilities',
    ],
)