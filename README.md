# Shaheed Rajib Anmol Free Education System — Student Portal

A beginner-friendly PHP registration and login application demonstrating HTTP form handling, validation, sessions, superglobals, redirects and safe output escaping.

## Requirements

- PHP 8.0 or later (tested with PHP 8.4)
- Local PHP development server or XAMPP with Apache
- No database required

## Project Structure

```text
BE-03/
├── index.php
├── README.md
├── .gitignore
├── includes/
│   ├── config.php
│   └── functions.php
└── assets/
    └── css/
        └── style.css
```

## Run with PHP Built-in Development Server

Open CMD in the project directory:

```cmd
php -S localhost:8000
```

Open:

http://localhost:8000

Keep CMD open while using the application. Press Ctrl+C to stop the server.

## Run with XAMPP

1. Copy the BE-03 project folder into `C:\xampp\htdocs\`.
2. Start Apache using XAMPP Control Panel.
3. MySQL is not required.
4. Open:

http://localhost/BE-03/

## Demonstration Login Credentials

Use these credentials for local testing:

- Email: `demo@school.test`
- Password: `School@123`

These are demonstration credentials only. They are not real school account credentials and must not be reused in production.

You may also register a new account and sign in during the same PHP session.

Registration data is stored in the current session only. There is no database or permanent account storage. Registered passwords are stored as password hashes, not plain text.

## Form Processing

- Registration and login forms use POST.
- GET is used for navigation and selecting the active form.
- Successful and failed POST requests use HTTP 303 redirects to prevent accidental resubmission.
- Registration validates required fields, email format, phone number, gender, password length and password confirmation.
- CSRF tokens protect form submissions.
- Passwords are never displayed or retained in form recovery values.
- User-provided values are escaped with `htmlspecialchars()` before display.

## HTTP Methods

This HTML form application accepts GET and POST.

PUT, PATCH and DELETE are commonly used by API clients to update or remove resources. This application does not expose those API operations.

Unsupported HTTP methods receive status 405 with an `Allow: GET, POST` header.

## HTTP Response Codes

- 200: Normal page response.
- 303: Redirect after form submission.
- 403: Invalid or expired CSRF token.
- 405: Unsupported HTTP method.

## PHP Superglobals

- `$_GET`: Reads the selected navigation view.
- `$_POST`: Receives registration, login and logout form data.
- `$_SERVER`: Reads the request method, script path and HTTPS state.
- `$_SESSION`: Stores CSRF tokens, flash messages, the session-only registered account and authentication state.
- `$_COOKIE`: PHP's session handler uses the session cookie to identify the current session. The application does not need to read it manually.
- `$_REQUEST`: Intentionally avoided because it merges GET, POST and COOKIE values, making the source of data ambiguous.
- `$_FILES`: Not used because this registration form does not contain a file-upload field.
- `$_ENV`: Not required for this fixed local demonstration configuration.

## Syntax Verification

Run:

```cmd
php -l index.php
php -l includes/config.php
php -l includes/functions.php
```

## Security Note

This is an educational demonstration, not a production authentication system.

It uses PHP sessions and a predefined sample account instead of a database, persistent user management, account recovery or production deployment controls.

Use HTTPS and a proper persistent user store before adapting this project for real users.
