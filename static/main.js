function slider() {
  const signUpButton = document.getElementById('signUp');
  const signInButton = document.getElementById('signIn');
  const container = document.getElementById('container');

  signUpButton.addEventListener('click', () => container.classList.add('right-panel-active'));

  signInButton.addEventListener('click', () => container.classList.remove('right-panel-active'));
}

function copyFunction(id) {
  /* Get the text field */
  var copyText = document.getElementById(id);

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

if (!document.location.hash) {
  document.location.hash = 'check';
}

var element = $('.scrolling-wrapper-flexbox').get(0);
var left = element.scrollWidth;
element.scrollLeft = left;

// Confirmation Display on Voting.html

function confirmFunction() {
  var rad = document.vote_form.candidate;
  var prev = null;
  for (var i = 0; i < rad.length; i++) {
    rad[i].addEventListener('change', function() {
      prev ? console.log(prev.value) : null;
      if (this !== prev) {
        prev = this;
      }
      console.log(this.value);
      document.getElementById('confirmation').innerHTML = this.value;
      document.getElementById('confirmation_info').innerHTML = '<hr> Your selected candidate:';
    });
  }
}
