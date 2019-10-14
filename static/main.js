function slider() {
  const signUpButton = document.getElementById('signUp');
  const signInButton = document.getElementById('signIn');
  const container = document.getElementById('container');

  signUpButton.addEventListener('click', () => container.classList.add('right-panel-active'));

  signInButton.addEventListener('click', () => container.classList.remove('right-panel-active'));
}

function copyFunction() {
  /* Get the text field */
  var copyText = document.getElementById('copy_privateKey');

  /* Select the text field */
  copyText.select();
  copyText.setSelectionRange(0, 99999); /*For mobile devices*/

  /* Copy the text inside the text field */
  document.execCommand('copy');

  /* Alert the copied text */
  alert('Copied the text: ' + copyText.value);
}

$('#myModal').on('shown.bs.modal', function() {
  $('#myInput').focus();
});
