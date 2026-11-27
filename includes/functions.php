<?php

declare(strict_types=1);

require_once __DIR__ . '/config.php';


// Escape dynamic values before inserting them into HTML.
function e(string|int|float|null $value): string
{
    return htmlspecialchars(
        (string) $value,
        ENT_QUOTES | ENT_SUBSTITUTE,
        'UTF-8'
    );
}


// Redirect after a POST request to prevent accidental resubmission.
function redirectTo(string $location): void
{
    header('Location: ' . $location, true, 303);

    exit;
}


// Store a message for display after a redirect.
function setFlashMessage(string $type, string $message): void
{
    $_SESSION['flash_message'] = [
        'type' => $type,
        'message' => $message,
    ];
}


// Retrieve and remove the message after displaying it once.
function consumeFlashMessage(): ?array
{
    $message = $_SESSION['flash_message'] ?? null;

    unset($_SESSION['flash_message']);

    return is_array($message) ? $message : null;
}


// Compare the submitted security token with the session token.
function isValidCsrfToken(mixed $submittedToken): bool
{
    return is_string($submittedToken)
        && isset($_SESSION['csrf_token'])
        && is_string($_SESSION['csrf_token'])
        && hash_equals(
            $_SESSION['csrf_token'],
            $submittedToken
        );
}


// Validate all registration fields.
function validateRegistrationInput(array $input): array
{
    $errors = [];

    // Receive only string values and remove unnecessary whitespace.
    $fullName = trim(
        is_string($input['full_name'] ?? null)
        ? $input['full_name']
        : ''
    );

    $email = strtolower(
        trim(
            is_string($input['email'] ?? null)
            ? $input['email']
            : ''
        )
    );

    $phone = trim(
        is_string($input['phone'] ?? null)
        ? $input['phone']
        : ''
    );

    $gender = is_string($input['gender'] ?? null)
        ? $input['gender']
        : '';

    $password = is_string($input['password'] ?? null)
        ? $input['password']
        : '';

    $confirmPassword = is_string($input['confirm_password'] ?? null)
        ? $input['confirm_password']
        : '';


    // Retain only non-sensitive values when validation fails.
    $old = [
        'full_name' => $fullName,
        'email' => $email,
        'phone' => $phone,
        'gender' => $gender,
    ];


    // Full name validation.
    if ($fullName === '') {

        $errors['full_name'] = 'Please enter your full name.';

    } elseif (strlen($fullName) > 100) {

        $errors['full_name'] = 'Your name must not exceed 100 characters.';

    }


    // Email validation.
    if ($email === '') {

        $errors['email'] = 'Please enter your email address.';

    } elseif (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {

        $errors['email'] = 'Please enter a valid email address.';

    } elseif ($email === DEMO_LOGIN_EMAIL) {

        $errors['email'] = 'This email is reserved for the demonstration account.';

    }


    // Phone number validation.
    if ($phone === '') {

        $errors['phone'] = 'Please enter your phone number.';

    } elseif (preg_match('/^\+?[0-9\s().-]+$/', $phone) !== 1) {

        $errors['phone'] = 'Use only digits, spaces, +, parentheses, dots or hyphens.';

    } else {

        $digits = preg_replace('/\D+/', '', $phone) ?? '';

        if (strlen($digits) < 7 || strlen($digits) > 15) {

            $errors['phone'] = 'Your phone number must contain 7 to 15 digits.';

        }

    }


    // Gender selection validation.
    $allowedGenders = [
        'female',
        'male',
        'other',
        'prefer_not_to_say'
    ];

    if (!in_array($gender, $allowedGenders, true)) {

        $errors['gender'] = 'Please select a valid option.';

    }


    // Password validation.
    if ($password === '') {

        $errors['password'] = 'Please create a password.';

    } elseif (strlen($password) < 8) {

        $errors['password'] = 'Your password must contain at least 8 characters.';

    }


    // Confirm password validation.
    if ($confirmPassword === '') {

        $errors['confirm_password'] = 'Please confirm your password.';

    } elseif (!hash_equals($password, $confirmPassword)) {

        $errors['confirm_password'] = 'The passwords do not match.';

    }


    return [
        'errors' => $errors,
        'old' => $old,
        'password' => $password,
    ];
}


// Authenticate a predefined demo account or a registered session account.
function authenticateUser(string $email, string $password): ?array
{
    // Check the predefined demonstration account.
    if (hash_equals(DEMO_LOGIN_EMAIL, $email)) {

        // Generate a password hash for the demonstration check.
        $demoPasswordHash = password_hash(
            DEMO_LOGIN_PASSWORD,
            PASSWORD_DEFAULT
        );

        if (password_verify($password, $demoPasswordHash)) {

            return [
                'full_name' => 'Demo Student',
                'email' => DEMO_LOGIN_EMAIL,
            ];

        }

    }


    // Check the account registered in the current PHP session.
    $registeredUser = $_SESSION['registered_user'] ?? null;

    if (
        is_array($registeredUser)
        && isset(
        $registeredUser['email'],
        $registeredUser['password_hash']
    )
        && is_string($registeredUser['email'])
        && is_string($registeredUser['password_hash'])
        && hash_equals($registeredUser['email'], $email)
        && password_verify(
            $password,
            $registeredUser['password_hash']
        )
    ) {

        return [
            'full_name' => (string) (
                $registeredUser['full_name'] ?? 'Student'
            ),
            'email' => $registeredUser['email'],
        ];

    }

    // Return null when authentication fails.
    return null;
}