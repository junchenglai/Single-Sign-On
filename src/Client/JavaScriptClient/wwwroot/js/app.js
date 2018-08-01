/// <reference path="oidc-client.js" />

let config = {
    authority: 'http://localhost:5000/',
    client_id: 'js',
    redirect_uri: 'http://localhost:5003/callback.html',
    response_type: 'id_token token',
    scope: 'openid profile phone email address',
};

const mgr = new Oidc.UserManager(config)

function log() {
    document.getElementById('results').innerText = '';

    Array.prototype.forEach.call(arguments, function (msg) {
        if (msg instanceof Error) {
            msg = "错误：" + msg.message;
        }
        else if (typeof msg !== 'string') {
            msg = JSON.stringify(msg, null, 2);
        }
        document.getElementById('results').innerHTML += msg + '\r\n';
    });
}

document.getElementById("login").addEventListener("click", login, false);
document.getElementById("signup").addEventListener("click", signup, false);
document.getElementById("logout").addEventListener("click", logout, false);

mgr.getUser().then((user) => {
    if (user) {
        log("用户已登录", user.profile);
    }
    else {
        log("用户未登录");
    }
});

// 当检测用户退出系统时，强行退出
window.onmessage = function (e) {
    this.console.log(e.data)
    if (e.data === "change") mgr.removeUser();
}

function login() {
    mgr.signinRedirect();
}

function logout() {
    mgr.signoutRedirect();
}

function signup() {
    window.location.href = config.authority + "account/signup";
}