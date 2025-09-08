<?php
$token = '';
if(isset($_COOKIE['token'])) {
    $token = $_COOKIE['token'];
    //header("Location: " . str_replace('$token', $token, $_GET['redirect']));
}
?><!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Single Sign-On</title>
</head>
<body>
    <form method="POST" action="login.php">
        <input type="hidden" name="redirect" value="<?=$_GET['redirect']?>">
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit">Login</button>
    </form>
    <?php
    if($token):
    ?>
    <script>
    (function () {
        var fn = 'onLogin';
        try {
            if (window.opener && !window.opener.closed) {
                window.opener.postMessage({ type: fn, token: <?= json_encode(['token' => $token]) ?> }, '*');
            }
        } catch (e) {
            console.warn('Login callback error:', e);
        }
        try { window.close(); } catch (_) {}
    })();
</script>
<?php endif; ?>
</body>
</html>