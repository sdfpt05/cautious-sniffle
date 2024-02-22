# Data Privacy Vault

Data Privacy Vault is a command-line interface (CLI) application written in Python that allows multiple users to securely manage their credentials. Users can log in, view their credentials, and add new credentials.

## Features

- User registration and login system
- Secure storage of user credentials
- View and add credentials for the logged-in user
- Password hashing for enhanced security

## Prerequisites

- Python 3.x
- `pipenv` (install via `pip install pipenv`)
- SQLite (or another supported database)

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/sdfpt04/data-privacy-vault.git
    ```

2. Navigate to the project directory:

    ```bash
    cd data-privacy-vault
    ```

3. Install dependencies using `pipenv`:

    ```bash
    pipenv install
    ```

4. Activate the virtual environment:

    ```bash
    pipenv shell
    ```

## Usage

1. Run the application:

    ```bash
    python main.py
    ```

2. Choose the desired options from the menu:

    - **Register:** Create a new user account.
    - **Login:** Log in with an existing account to manage credentials.
    - **View Credentials:** View stored credentials.
    - **Add Credential:** Add a new credential.

3. Follow the on-screen prompts to interact with the application.

## Database

The application uses SQLite by default. You can change the database configuration in `data_privacy_vault/cli.py`.

## Contributing

If you'd like to contribute to this project, please follow these steps:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/your-feature`).
3. Commit your changes (`git commit -am 'Add your feature'`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Create a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

## Acknowledgments

- [Click](https://click.palletsprojects.com/en/7.x/) - A Python package for creating beautiful command-line interfaces.
- [SQLAlchemy](https://www.sqlalchemy.org/) - SQL toolkit and Object-Relational Mapping (ORM) for Python.
- [Colorama](https://pypi.org/project/colorama/) - Simple cross-platform colored terminal text.

