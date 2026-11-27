<?php

declare(strict_types=1);

require_once __DIR__ . '/includes/config.php';

require_once __DIR__ . '/includes/functions.php';


// Configure secure session cookie settings.
$isHttps = isset($_SERVER['HTTPS'])
    && $_SERVER['HTTPS'] !== 'off';

session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => $isHttps,
    'httponly' => true,
    'samesite' => 'Lax',
]);


// Enable safer session handling.
ini_set('session.use_strict_mode', '1');

ini_set('session.use_only_cookies', '1');

session_start();


// Create a CSRF token for form protection.
if (
    !isset($_SESSION['csrf_token'])
    || !is_string($_SESSION['csrf_token'])
) {

    $_SESSION['csrf_token'] = bin2hex(
        random_bytes(32)
    );

}


// Read the incoming HTTP request method.
$requestMethod = $_SERVER['REQUEST_METHOD'] ?? 'GET';

$requestError = '';


// Accept GET and POST for this HTML form application.
if (!in_array($requestMethod, ['GET', 'POST'], true)) {

    header('Allow: GET, POST');

    http_response_code(405);

    exit('Method Not Allowed');

}


// Process form submissions.
if ($requestMethod === 'POST') {

    $action = $_POST['form_action'] ?? '';

    if (!is_string($action)) {
        $action = '';
    }


    // Verify the CSRF security token before processing any form.
    if (!isValidCsrfToken($_POST['csrf_token'] ?? null)) {

        http_response_code(403);

        $requestError = 'Your form session has expired. Refresh the page and try again.';

    }


    // Registration form processing.
    elseif ($action === 'register') {

        $registration = validateRegistrationInput($_POST);

        $errors = $registration['errors'];

        $old = $registration['old'];


        // Prevent registering the same email twice in this session.
        $existingRegistration = $_SESSION['registered_user'] ?? null;

        if (
            $errors === []
            && is_array($existingRegistration)
            && strtolower(
                (string) ($existingRegistration['email'] ?? '')
            ) === $old['email']
        ) {

            $errors['email'] = 'An account with this email is already registered in this browser session.';

        }


        // Redirect back with validation errors.
        if ($errors !== []) {

            $_SESSION['registration_errors'] = $errors;

            $_SESSION['registration_old'] = $old;

            redirectTo('index.php?view=register#register');

        }


        // Save the registered account using a password hash.
        $_SESSION['registered_user'] = [

            'full_name' => $old['full_name'],

            'email' => $old['email'],

            'phone' => $old['phone'],

            'gender' => $old['gender'],

            'password_hash' => password_hash(
                $registration['password'],
                PASSWORD_DEFAULT
            ),

        ];


        setFlashMessage(
            'success',
            'Your registration was completed for this browser session. You can now sign in with the email and password you registered.'
        );

        redirectTo('index.php?view=login#login');

    }


    // Login form processing.
    elseif ($action === 'login') {

        $emailValue = $_POST['email'] ?? '';

        $passwordValue = $_POST['password'] ?? '';


        // Normalize the email but never trim or display the password.
        $email = is_string($emailValue)
            ? strtolower(trim($emailValue))
            : '';

        $password = is_string($passwordValue)
            ? $passwordValue
            : '';


        // Keep only the non-sensitive email for form recovery.
        $_SESSION['login_old_email'] = $email;


        // Validate login fields.
        if (
            $email === ''
            || filter_var($email, FILTER_VALIDATE_EMAIL) === false
            || $password === ''
        ) {

            setFlashMessage(
                'error',
                'Enter a valid email address and password.'
            );

            redirectTo('index.php?view=login#login');

        }


        // Authenticate the submitted account.
        $authenticatedUser = authenticateUser(
            $email,
            $password
        );


        // Reject incorrect credentials.
        if ($authenticatedUser === null) {

            setFlashMessage(
                'error',
                'The email address or password is incorrect.'
            );

            redirectTo('index.php?view=login#login');

        }


        // Regenerate the session ID after successful authentication.
        session_regenerate_id(true);

        $_SESSION['csrf_token'] = bin2hex(
            random_bytes(32)
        );

        $_SESSION['authenticated_user'] = $authenticatedUser;

        unset($_SESSION['login_old_email']);


        setFlashMessage(
            'success',
            'You are now signed in. Welcome to your student portal.'
        );

        redirectTo('index.php?view=login#login');

    }


    // Logout processing.
    elseif ($action === 'logout') {

        unset($_SESSION['authenticated_user']);

        session_regenerate_id(true);

        $_SESSION['csrf_token'] = bin2hex(
            random_bytes(32)
        );


        setFlashMessage(
            'success',
            'You have been signed out successfully.'
        );

        redirectTo('index.php?view=login#login');

    }


    // Reject unknown form actions.
    else {

        http_response_code(400);

        $requestError = 'The submitted form action is not valid.';

    }

}


// Retrieve one-time flash messages.
$flashMessage = consumeFlashMessage();


// Retrieve registration validation errors.
$registrationErrors = $_SESSION['registration_errors'] ?? [];

$registrationOld = $_SESSION['registration_old'] ?? [];

$loginOldEmail = $_SESSION['login_old_email'] ?? '';


// Remove temporary values after reading them.
unset(
    $_SESSION['registration_errors'],
    $_SESSION['registration_old'],
    $_SESSION['login_old_email']
);


// Verify session values before using them.
if (!is_array($registrationErrors)) {
    $registrationErrors = [];
}

if (!is_array($registrationOld)) {
    $registrationOld = [];
}

if (!is_string($loginOldEmail)) {
    $loginOldEmail = '';
}


// Check whether a user is authenticated.
$authenticatedUser = $_SESSION['authenticated_user'] ?? null;

if (!is_array($authenticatedUser)) {
    $authenticatedUser = null;
}


// Prepare values used by the HTML page.
$csrfToken = $_SESSION['csrf_token'];

$activeView = $_GET['view'] ?? 'register';

if (
    !is_string($activeView)
    || !in_array($activeView, ['register', 'login'], true)
) {

    $activeView = 'register';

}

$scriptName = $_SERVER['SCRIPT_NAME'] ?? 'index.php';

?>

<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <meta
        name="description"
        content="Student registration and secure access portal for Shaheed Rajib Anmol Free Education System."
    >

    <title><?= e(SCHOOL_NAME) ?> | Student Portal</title>

    <link rel="stylesheet" href="assets/css/style.css">

</head>


<body>

    <div class="site-shell">


        <!-- School branding and navigation -->
        <header class="site-header">

            <a class="brand" href="index.php" aria-label="School home">

                <span class="brand-mark">
                    SRA
                </span>

                <span class="brand-copy">

                    <strong><?= e(SCHOOL_NAME) ?></strong>

                    <small><?= e(SCHOOL_TAGLINE) ?></small>

                </span>

            </a>


            <nav class="main-nav" aria-label="Main navigation">

                <a
                    class="<?= $activeView === 'register' ? 'active' : '' ?>"
                    href="index.php?view=register#register"
                >
                    Create account
                </a>

                <a
                    class="<?= $activeView === 'login' ? 'active' : '' ?>"
                    href="index.php?view=login#login"
                >
                    Student login
                </a>

            </nav>

        </header>


        <main>


            <!-- Welcome section -->
            <section class="welcome-panel">

                <div class="welcome-copy">

                    <p class="eyebrow">STUDENT SERVICES</p>

                    <h1>A place to learn, grow and move forward.</h1>

                    <p>
                        Register your details or sign in to continue
                        to the student portal of
                        Shaheed Rajib Anmol Free Education System.
                    </p>

                </div>


                <div class="welcome-emblem" aria-hidden="true">

                    <span>LEARN</span>

                    <strong>★</strong>

                    <span>ACHIEVE</span>

                </div>

            </section>


            <!-- Display request errors -->
            <?php if ($requestError !== ''): ?>

                    <div class="alert error-alert" role="alert">

                        <?= e($requestError) ?>

                    </div>

            <?php endif; ?>


            <!-- Display one-time success or failure messages -->
            <?php if (
                is_array($flashMessage)
                && isset($flashMessage['type'], $flashMessage['message'])
            ): ?>

                    <div
                        class="alert <?= $flashMessage['type'] === 'success' ? 'success-alert' : 'error-alert' ?>"
                        role="alert"
                    >

                        <?= e(
                            is_string($flashMessage['message'])
                            ? $flashMessage['message']
                            : ''
                        ) ?>

                    </div>

            <?php endif; ?>


            <section class="portal-grid">


                <!-- Student registration form -->
                <article class="form-card" id="register">

                    <div class="card-heading">

                        <span class="step-label">NEW STUDENT</span>

                        <h2>Create your account</h2>

                        <p>
                            Enter your details to complete the registration form.
                        </p>

                    </div>


                    <form
                        method="POST"
                        action="<?= e($scriptName) ?>#register"
                        novalidate
                    >

                        <input
                            type="hidden"
                            name="form_action"
                            value="register"
                        >

                        <input
                            type="hidden"
                            name="csrf_token"
                            value="<?= e($csrfToken) ?>"
                        >


                        <div class="form-field">

                            <label for="full_name">Full name</label>

                            <input
                                id="full_name"
                                name="full_name"
                                type="text"
                                maxlength="100"
                                autocomplete="name"
                                required
                                value="<?= e(is_string($registrationOld['full_name'] ?? null) ? $registrationOld['full_name'] : '') ?>"
                                aria-invalid="<?= isset($registrationErrors['full_name']) ? 'true' : 'false' ?>"
                            >

                            <?php if (isset($registrationErrors['full_name'])): ?>

                                    <small class="field-error">

                                        <?= e($registrationErrors['full_name']) ?>

                                    </small>

                            <?php endif; ?>

                        </div>


                        <div class="form-field">

                            <label for="register_email">Email address</label>

                            <input
                                id="register_email"
                                name="email"
                                type="email"
                                maxlength="254"
                                autocomplete="email"
                                required
                                value="<?= e(is_string($registrationOld['email'] ?? null) ? $registrationOld['email'] : '') ?>"
                                aria-invalid="<?= isset($registrationErrors['email']) ? 'true' : 'false' ?>"
                            >

                            <?php if (isset($registrationErrors['email'])): ?>

                                    <small class="field-error">

                                        <?= e($registrationErrors['email']) ?>

                                    </small>

                            <?php endif; ?>

                        </div>


                        <div class="form-row">


                            <div class="form-field">

                                <label for="phone">Phone number</label>

                                <input
                                    id="phone"
                                    name="phone"
                                    type="tel"
                                    maxlength="20"
                                    autocomplete="tel"
                                    placeholder="+92 300 1234567"
                                    required
                                    value="<?= e(is_string($registrationOld['phone'] ?? null) ? $registrationOld['phone'] : '') ?>"
                                    aria-invalid="<?= isset($registrationErrors['phone']) ? 'true' : 'false' ?>"
                                >

                                <?php if (isset($registrationErrors['phone'])): ?>

                                        <small class="field-error">

                                            <?= e($registrationErrors['phone']) ?>

                                        </small>

                                <?php endif; ?>

                            </div>


                            <div class="form-field">

                                <label for="gender">Gender</label>

                                <select
                                    id="gender"
                                    name="gender"
                                    required
                                    aria-invalid="<?= isset($registrationErrors['gender']) ? 'true' : 'false' ?>"
                                >

                                    <option value="">Select option</option>

                                    <option
                                        value="female"
                                        <?= ($registrationOld['gender'] ?? '') === 'female' ? 'selected' : '' ?>
                                    >
                                        Female
                                    </option>

                                    <option
                                        value="male"
                                        <?= ($registrationOld['gender'] ?? '') === 'male' ? 'selected' : '' ?>
                                    >
                                        Male
                                    </option>

                                    <option
                                        value="other"
                                        <?= ($registrationOld['gender'] ?? '') === 'other' ? 'selected' : '' ?>
                                    >
                                        Other
                                    </option>

                                    <option
                                        value="prefer_not_to_say"
                                        <?= ($registrationOld['gender'] ?? '') === 'prefer_not_to_say' ? 'selected' : '' ?>
                                    >
                                        Prefer not to say
                                    </option>

                                </select>

                                <?php if (isset($registrationErrors['gender'])): ?>

                                        <small class="field-error">

                                            <?= e($registrationErrors['gender']) ?>

                                        </small>

                                <?php endif; ?>

                            </div>

                        </div>


                        <div class="form-row">


                            <div class="form-field">

                                <label for="password">Password</label>

                                <input
                                    id="password"
                                    name="password"
                                    type="password"
                                    minlength="8"
                                    autocomplete="new-password"
                                    required
                                >

                                <?php if (isset($registrationErrors['password'])): ?>

                                        <small class="field-error">

                                            <?= e($registrationErrors['password']) ?>

                                        </small>

                                <?php endif; ?>

                            </div>


                            <div class="form-field">

                                <label for="confirm_password">
                                    Confirm password
                                </label>

                                <input
                                    id="confirm_password"
                                    name="confirm_password"
                                    type="password"
                                    minlength="8"
                                    autocomplete="new-password"
                                    required
                                >

                                <?php if (isset($registrationErrors['confirm_password'])): ?>

                                        <small class="field-error">

                                            <?= e($registrationErrors['confirm_password']) ?>

                                        </small>

                                <?php endif; ?>

                            </div>

                        </div>


                        <p class="form-note">

                            Passwords are never shown in the page.
                            This learning project keeps the registered
                            account in the current PHP session only.

                        </p>


                        <button
                            class="primary-button"
                            type="submit"
                        >
                            Complete registration
                        </button>

                    </form>

                </article>


                <!-- Login form or authenticated account -->
                <article class="form-card login-card" id="login">


                    <?php if ($authenticatedUser !== null): ?>


                            <div class="card-heading">

                                <span class="step-label">SIGNED IN</span>

                                <h2>
                                    Welcome,
                                    <?= e(
                                        is_string($authenticatedUser['full_name'] ?? null)
                                        ? $authenticatedUser['full_name']
                                        : 'Student'
                                    ) ?>
                                </h2>

                                <p>Your student portal session is active.</p>

                            </div>


                            <div class="account-summary">

                                <span class="account-avatar">✓</span>

                                <div>

                                    <strong>

                                        <?= e(
                                            is_string($authenticatedUser['email'] ?? null)
                                            ? $authenticatedUser['email']
                                            : ''
                                        ) ?>

                                    </strong>

                                    <small>Authenticated student account</small>

                                </div>

                            </div>


                            <form
                                method="POST"
                                action="<?= e($scriptName) ?>#login"
                            >

                                <input
                                    type="hidden"
                                    name="form_action"
                                    value="logout"
                                >

                                <input
                                    type="hidden"
                                    name="csrf_token"
                                    value="<?= e($csrfToken) ?>"
                                >

                                <button
                                    class="secondary-button"
                                    type="submit"
                                >
                                    Sign out
                                </button>

                            </form>


                    <?php else: ?>


                            <div class="card-heading">

                                <span class="step-label">RETURNING STUDENT</span>

                                <h2>Sign in to your account</h2>

                                <p>
                                    Use your registered details or the
                                    demonstration account.
                                </p>

                            </div>


                            <form
                                method="POST"
                                action="<?= e($scriptName) ?>#login"
                            >

                                <input
                                    type="hidden"
                                    name="form_action"
                                    value="login"
                                >

                                <input
                                    type="hidden"
                                    name="csrf_token"
                                    value="<?= e($csrfToken) ?>"
                                >


                                <div class="form-field">

                                    <label for="login_email">Email address</label>

                                    <input
                                        id="login_email"
                                        name="email"
                                        type="email"
                                        autocomplete="username"
                                        required
                                        value="<?= e($loginOldEmail) ?>"
                                    >

                                </div>


                                <div class="form-field">

                                    <label for="login_password">Password</label>

                                    <input
                                        id="login_password"
                                        name="password"
                                        type="password"
                                        autocomplete="current-password"
                                        required
                                    >

                                </div>


                                <button
                                    class="primary-button"
                                    type="submit"
                                >
                                    Sign in
                                </button>

                            </form>


                            <div class="demo-note">

                                <strong>Demo access</strong>

                                <p>
                                    Sample login credentials are provided
                                    in the project README for local testing.
                                </p>

                            </div>


                    <?php endif; ?>


                </article>

            </section>

        </main>


        <!-- School footer -->
        <footer class="site-footer">

            <strong><?= e(SCHOOL_NAME) ?></strong>

            <span>Student Registration and Access Portal</span>

        </footer>

    </div>

</body>

</html>
