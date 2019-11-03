// Copy the Private Key to the Clipboard on the verification.html
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

// Bootstrap function to enable Modals
$('#myModal').on('shown.bs.modal', function() {
  $('#myInput').focus();
});

// Lets the Verify.html start with the verified vote after using that feature
if (!document.location.hash) {
  document.location.hash = 'check';
}

// Letting Blockchain Viewer start with the most recent Block
var element = $('.scrolling-wrapper-flexbox').get(0);
var left = element.scrollWidth;
element.scrollLeft = left;

// Displaying the selected candidate on the voting.html as part of the confirmation
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
