/*
 * INTENTIONALLY INSECURE JAVASCRIPT FIXTURE.
 * Used only to verify the scanner's JavaScript/TypeScript regex rules.
 */

const api_key = "sk_live_frontend_example";

function renderComment(userInput) {
  document.body.innerHTML = userInput;
}

function redirect(nextUrl) {
  window.location.href = nextUrl;
}

function runShell(command) {
  exec(command);
}
