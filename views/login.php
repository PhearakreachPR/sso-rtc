<?php
header('Access-Control-Allow-Origin: *');
header('SameSite=None');
$allowedUsers = [
    ['username' => 'user', 'password' => 'pass','token' => 'user_token'],
    ['username' => 'admin', 'password' => 'admin','token' => 'admin_token']
];
session_start();
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];
    $redirect = $_POST['redirect'];

    // Here you would typically check the username and password against a database
    foreach ($allowedUsers as $user) {
        if ($username === $user['username'] && $password === $user['password']) {
            $_SESSION['user_id'] = $username;
            setcookie('token', $user['token'], time() + 3600, '/');
            // header("Location: " . str_replace('$token', $user['token'], $redirect));
            ?><script>
    (function () {
        var fn = 'onLogin';
        try {
            if (window.opener && !window.opener.closed) {
                window.opener.postMessage({ type: fn, token: <?= json_encode(['token' => $user['token']]) ?> }, '*');
                //var o = window.opener;
                //if (typeof o[fn] === 'function') {
                    //o[fn](<?= json_encode(['token' => $user['token']]) ?>);
                //}
            }
        } catch (e) {
            console.warn('Login callback error:', e);
        }
        try { window.close(); } catch (_) {}
    })();
</script><?php
            exit();
        }
    }
    // echo "Invalid credentials";
    // header("Location: http://localhost:4200/index.php?error=1&redirect=$redirect");
    header("Location: http://localhost:3000'/index.php?error=1&redirect=$redirect");
}else{
    echo "Invalid credentials";
    exit();
}?>