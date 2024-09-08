# Data Privacy Vault

A secure credential management system with both CLI and web interfaces.

## Features

- User registration and authentication
- Secure storage of credentials
- Encryption of sensitive data
- CLI interface for easy local access
- Web API for remote access and integration

## Setup

1. Clone the repository:

   ```
   git clone https://github.com/yourusername/data-privacy-vault.git
   cd data-privacy-vault
   ```

2. Set up a virtual environment:

   ```
   python -m venv venv
   source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
   ```

3. Install dependencies:

   ```
   pip install -r data_vault_cli/requirements.txt
   pip install -r data_vault_web/requirements.txt
   ```

4. Set up environment variables:
   Create a `.env` file in the root directory with the following content:
   ```
   DATABASE_URL=sqlite:///data_vault.db
   SECRET_KEY=your-secret-key
   JWT_SECRET_KEY=your-jwt-secret-key
   ENCRYPTION_SECRET=your-encryption-secret
   ```

## Usage

### CLI Interface

Run the CLI application:

```
python data_vault_cli/run.py
```

### Web Interface

Run the web application:

```
python data_vault_web/app.py
```

## API Endpoints

- POST /auth/register - Register a new user
- POST /auth/login - Login and receive JWT token
- GET /api/credentials - Get all credentials (requires authentication)
- POST /api/credentials - Add a new credential (requires authentication)
- PUT /api/credentials/<id> - Update a credential (requires authentication)
- DELETE /api/credentials/<id> - Delete a credential (requires authentication)

## Security Considerations

- All sensitive data is encrypted before storage
- Passwords are hashed using strong algorithms
- JWT is used for API authentication
- Environment variables are used for sensitive configuration

## Contributing

Please read CONTRIBUTING.md for details on our code of conduct, and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
