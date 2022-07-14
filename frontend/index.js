const API_URL = "http://127.0.0.1:8000"

function logged_in() {
    let flag = false;

    let token = window.localStorage.getItem('token');

    if(token != null && token.length >= 40) {
        flag = !flag;
    }

    token = null;

    return flag;
}

function ensure_logged_in({ redirect: page }) {

    let token = window.localStorage.getItem('token');

    if(token != null && token.length >= 40) {
        token = null;
        return;
    }

    window.location.replace(page);
}

function set_error_message(string) {
    window.localStorage.setItem('error_message', string);
}

function set_success_message(string) {
    window.localStorage.setItem('success_message', string);
}

function showMessageNotification(message, status) {
    let message_notification = document.getElementById('message-notification');

    if (status == "success") {
        message_notification.classList.remove('d-none');
        message_notification.classList.add('alert-success');
        message_notification.innerHTML = message;
    }

    if (status == "error") {
        message_notification.classList.remove('d-none');
        message_notification.classList.add('alert-danger');
        message_notification.innerHTML = message;
    }
}

function check_admin_or_staff({redirect: page}) {
    $.ajax({
        url: `${API_URL}/api/user-group/`,
        method: 'GET',
        dataType: 'json',
        headers: {
            'Authorization' : `Token ${window.localStorage.token}`
        },
        success: (res) => {

            if(res.is_admin || res.group == 'staff') {
                return;
            }

            window.location.replace(page);
        },
        error: (res) => {
            window.location.replace(page);
        }
    });
}


try {
    let logout = document.getElementById('logout');
    logout.addEventListener('click', (e)=> {
        e.preventDefault();
        $.ajax({
            headers: {
                'Authorization': `Token ${window.localStorage.token}`
            },
            method:'GET',
            url: `${API_URL}/api/logout/`,
            dataType: 'json',
            success: (res) => {
                window.localStorage.removeItem('token');
                window.location.reload();
            },
            error: (res) => {
                window.localStorage.removeItem('token');
                window.location.reload();
            }
        });
    });
} catch (e) {}