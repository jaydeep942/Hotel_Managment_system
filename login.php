<?php
// We start a session to handle user data across pages if needed later on
session_start();

// --- DATABASE CONNECTION ---
// IMPORTANT: Change these details to match your database configuration
$db_host = "localhost";
$db_user = "root";
$db_pass = ""; // Your database password, often empty on a local setup
$db_name = "login";

// Create a connection to the database
$conn = new mysqli($db_host, $db_user, $db_pass, $db_name);

// Check if the connection failed and stop the script if it did
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// --- INITIALIZE VARIABLES ---
// These arrays will hold any error messages
$signup_errors = [];
$signin_errors = [];
// This variable will hold a success message after registration
$success_message = "";

// --- HANDLE SIGN UP REQUEST ---
// Check if the form was submitted by checking for the 'signup' button's name attribute
if (isset($_POST['signup'])) {
    // 1. Get and sanitize user input
    $name = trim($_POST['name']);
    $email = trim($_POST['email']);
    $password_plain = trim($_POST['password']);

    // 2. Validate the input
    if (empty($name)) { $signup_errors[] = "Name is required."; }
    if (empty($email)) { $signup_errors[] = "Email is required."; } 
    elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) { $signup_errors[] = "Invalid email format."; }
    if (empty($password_plain)) { $signup_errors[] = "Password is required."; } 
    elseif (strlen($password_plain) < 8) { $signup_errors[] = "Password must be at least 8 characters long."; }

    // 3. If validation passes, proceed to interact with the database
    if (empty($signup_errors)) {
        // First, check if the email already exists to prevent duplicates
        $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            $signup_errors[] = "An account with this email already exists.";
        } else {
            // The email is unique, so we can create the new account
            // SECURELY HASH THE PASSWORD before storing it
            $password_hashed = password_hash($password_plain, PASSWORD_DEFAULT);

            // Use a PREPARED STATEMENT to insert data, preventing SQL injection
            $insert_stmt = $conn->prepare("INSERT INTO users (name, email, password) VALUES (?, ?, ?)");
            $insert_stmt->bind_param("sss", $name, $email, $password_hashed);

            if ($insert_stmt->execute()) {
                $success_message = "Account created successfully! Please Sign In.";
            } else {
                $signup_errors[] = "Oops! Something went wrong. Please try again later.";
            }
            $insert_stmt->close();
        }
        $stmt->close();
    }
}

// --- HANDLE SIGN IN REQUEST ---
if (isset($_POST['signin'])) {
    // 1. Get user input
    $email = trim($_POST['email']);
    $password_plain = trim($_POST['password']);

    // 2. Validate input
    if (empty($email)) { $signin_errors[] = "Email is required."; }
    if (empty($password_plain)) { $signin_errors[] = "Password is required."; }

    // 3. If validation passes, check credentials
    if (empty($signin_errors)) {
        // Prepare a statement to find the user by email
        $stmt = $conn->prepare("SELECT id, name, password FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();

        // Check if a user with that email was found
        if ($stmt->num_rows > 0) {
            $stmt->bind_result($id, $name, $hashed_password);
            $stmt->fetch();

            // Verify the submitted password against the hashed password from the database
            if (password_verify($password_plain, $hashed_password)) {
                // Password is correct! Login is successful.
                // In a real application, you would set session variables here:
                // $_SESSION['user_id'] = $id;
                // $_SESSION['user_name'] = $name;
                // And then redirect to a dashboard: header("Location: dashboard.php");
                $success_message = "Welcome back, " . htmlspecialchars($name) . "!";
            } else {
                // Password was incorrect
                $signin_errors[] = "Invalid email or password.";
            }
        } else {
            // No user found with that email
            $signin_errors[] = "Invalid email or password.";
        }
        $stmt->close();
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Animated Login & Sign Up</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css">
    
    <style>
        /* All your original CSS styles are here */
        @import url('https://fonts.googleapis.com/css?family=Montserrat:400,800');
        * { box-sizing: border-box; }
        body { background: #f6f5f7; display: flex; justify-content: center; align-items: center; flex-direction: column; font-family: 'Montserrat', sans-serif; height: 100vh; margin: -20px 0 50px; }
        h1 { font-weight: bold; margin: 0; }
        p { font-size: 14px; font-weight: 100; line-height: 20px; letter-spacing: 0.5px; margin: 20px 0 30px; }
        span { font-size: 12px; }
        a { color: #333; font-size: 14px; text-decoration: none; margin: 15px 0; }
        button { border-radius: 20px; border: 1px solid #FF4B2B; background-color: #FF4B2B; color: #FFFFFF; font-size: 12px; font-weight: bold; padding: 12px 45px; letter-spacing: 1px; text-transform: uppercase; transition: transform 80ms ease-in; cursor: pointer; }
        button:active { transform: scale(0.95); }
        button:focus { outline: none; }
        button.ghost { background-color: transparent; border-color: #FFFFFF; }
        form { background-color: #FFFFFF; display: flex; align-items: center; justify-content: center; flex-direction: column; padding: 0 50px; height: 100%; text-align: center; }
        input { background-color: #eee; border: none; padding: 12px 15px; margin: 8px 0; width: 100%; }
        .container { background-color: #fff; border-radius: 10px; box-shadow: 0 14px 28px rgba(0,0,0,0.25), 0 10px 10px rgba(0,0,0,0.22); position: relative; overflow: hidden; width: 768px; max-width: 100%; min-height: 480px; }
        .form-container { position: absolute; top: 0; height: 100%; transition: all 0.6s ease-in-out; }
        .sign-in-container { left: 0; width: 50%; z-index: 2; }
        .sign-up-container { left: 0; width: 50%; opacity: 0; z-index: 1; }
        .social-container { margin: 20px 0; }
        .social-container a { border: 1px solid #DDDDDD; border-radius: 50%; display: inline-flex; justify-content: center; align-items: center; margin: 0 5px; height: 40px; width: 40px; }
        .overlay-container { position: absolute; top: 0; left: 50%; width: 50%; height: 100%; overflow: hidden; transition: transform 0.6s ease-in-out; z-index: 100; }
        .overlay { background: #FF416C; background: linear-gradient(to right, #FF4B2B, #FF416C); background-repeat: no-repeat; background-size: cover; background-position: 0 0; color: #FFFFFF; position: relative; left: -100%; height: 100%; width: 200%; transform: translateX(0); transition: transform 0.6s ease-in-out; }
        .overlay-panel { position: absolute; display: flex; align-items: center; justify-content: center; flex-direction: column; padding: 0 40px; text-align: center; top: 0; height: 100%; width: 50%; transform: translateX(0); transition: transform 0.6s ease-in-out; }
        .overlay-left { transform: translateX(-20%); }
        .overlay-right { right: 0; transform: translateX(0); }
        .container.right-panel-active .sign-in-container { transform: translateX(100%); }
        .container.right-panel-active .sign-up-container { transform: translateX(100%); opacity: 1; z-index: 5; animation: show 0.6s; }
        @keyframes show { 0%, 49.99% { opacity: 0; z-index: 1; } 50%, 100% { opacity: 1; z-index: 5; } }
        .container.right-panel-active .overlay-container { transform: translateX(-100%); }
        .container.right-panel-active .overlay { transform: translateX(50%); }
        .container.right-panel-active .overlay-left { transform: translateX(0); }
        .container.right-panel-active .overlay-right { transform: translateX(20%); }
        /* Simple styles for error and success messages */
        .message { padding: 10px; margin-bottom: 15px; border-radius: 5px; font-size: 14px; width: 100%; text-align: left; }
        .error { background-color: #f8d7da; color: #721c24; }
        .success { background-color: #d4edda; color: #155724; text-align: center;}
    </style>
</head>
<body>

    <div class="container <?php if(!empty($signup_errors) || (isset($_POST['signup']) && empty($success_message))) { echo 'right-panel-active'; } ?>" id="container">
        <div class="form-container sign-up-container">
            <form action="" method="POST">
                <h1>Create Account</h1>
                
                <?php if (!empty($signup_errors)): ?>
                    <div class="message error">
                        <?php foreach ($signup_errors as $error): ?>
                            <p><?php echo $error; ?></p>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>

                <span>or use your email for registration</span>
                <input type="text" name="name" placeholder="Name" required value="<?php echo isset($_POST['name']) ? htmlspecialchars($_POST['name']) : ''; ?>"/>
                <input type="email" name="email" placeholder="Email" required value="<?php echo isset($_POST['email']) ? htmlspecialchars($_POST['email']) : ''; ?>"/>
                <input type="password" name="password" placeholder="Password" required />
                <button type="submit" name="signup">Sign Up</button>
            </form>
        </div>

        <div class="form-container sign-in-container">
            <form action="" method="POST">
                <h1>Sign in</h1>
                
                 <?php if (!empty($signin_errors)): ?>
                    <div class="message error">
                        <?php foreach ($signin_errors as $error): ?>
                            <p><?php echo $error; ?></p>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
                <?php if (!empty($success_message)): ?>
                    <div class="message success">
                        <p><?php echo $success_message; ?></p>
                    </div>
                <?php endif; ?>
                
                <span>or use your account</span>
                <input type="email" name="email" placeholder="Email" required/>
                <input type="password" name="password" placeholder="Password" required/>
                <button type="submit" name="signin">Sign In</button>
            </form>
        </div>

        <div class="overlay-container">
            <div class="overlay">
                <div class="overlay-panel overlay-left">
                    <h1>Welcome Back!</h1>
                    <p>To keep connected with us please login with your personal info</p>
                    <button class="ghost" id="signIn">Sign In</button>
                </div>
                <div class="overlay-panel overlay-right">
                    <h1>Hello, Friend!</h1>
                    <p>Enter your personal details and start your journey with us</p>
                    <button class="ghost" id="signUp">Sign Up</button>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Your original JavaScript for the animation
        const signUpButton = document.getElementById('signUp');
        const signInButton = document.getElementById('signIn');
        const container = document.getElementById('container');

        signUpButton.addEventListener('click', () => {
            container.classList.add("right-panel-active");
        });

        signInButton.addEventListener('click', () => {
            container.classList.remove("right-panel-active");
        });
    </script>
</body>
</html>
<?php
// Close the database connection at the very end of the script
$conn->close();
?>