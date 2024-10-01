document.addEventListener('DOMContentLoaded', function() {   
    const button = document.querySelector('button');
    if (button) {
        button.addEventListener('click', function() {
            alert('Checking URL...');
        });
    }
});
