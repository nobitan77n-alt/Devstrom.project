const form = document.getElementById("passwordForm");
const passwordInput = document.getElementById("password");
const showButton = document.getElementById("showButton");
const checkButton = document.getElementById("checkButton");
const clearButton = document.getElementById("clearButton");
const meterFill = document.getElementById("meterFill");
const strengthLabel = document.getElementById("strengthLabel");
const strengthMessage = document.getElementById("strengthMessage");
const resultBox = document.getElementById("result");

// Show or hide the password.
showButton.addEventListener("click", function () {
  const isHidden = passwordInput.type === "password";
  passwordInput.type = isHidden ? "text" : "password";
  showButton.textContent = isHidden ? "Hide" : "Show";
});

// Calculate a simple local strength score while the user types.
passwordInput.addEventListener("input", function () {
  showStrength(passwordInput.value);
  hideResult();
});

function showStrength(password) {
  if (password.length === 0) {
    updateMeter(0, "Waiting", "Type a password to start the local strength check.");
    return;
  }

  let score = 0;

  if (password.length >= 8) score++;
  if (password.length >= 12) score++;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
  if (/\d/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;

  const commonPattern = /password|qwerty|123456|admin|welcome/i;
  if (commonPattern.test(password)) score -= 2;

  if (score <= 1) {
    updateMeter(1, "Weak", "Use more length and avoid common words or patterns.");
  } else if (score <= 3) {
    updateMeter(2, "Fair", "Add more length and mix different character types.");
  } else if (score === 4) {
    updateMeter(3, "Good", "This looks good, but still check the breach data.");
  } else {
    updateMeter(4, "Strong", "Strong local estimate. Now check the breach data.");
  }
}

function updateMeter(score, label, message) {
  const widths = ["0%", "25%", "50%", "75%", "100%"];
  const colors = ["transparent", "#ff6676", "#ffbe56", "#6ca9ff", "#4ce0bb"];

  meterFill.style.width = widths[score];
  meterFill.style.backgroundColor = colors[score];
  strengthLabel.textContent = label;
  strengthMessage.textContent = message;
}

// Check the password only when the form is submitted.
form.addEventListener("submit", async function (event) {
  event.preventDefault();

  let password = passwordInput.value;

  if (password.length === 0) {
    showResult("error", "Enter a password first.");
    passwordInput.focus();
    return;
  }

  checkButton.disabled = true;
  checkButton.textContent = "Checking...";
  hideResult();

  try {
    const fullHash = await createSha1(password);
    password = "";

    const prefix = fullHash.substring(0, 5);
    const suffix = fullHash.substring(5);

    const response = await fetch(
      "https://api.pwnedpasswords.com/range/" + prefix,
      { headers: { "Add-Padding": "true" } }
    );

    if (!response.ok) {
      throw new Error("Breach service error");
    }

    const responseText = await response.text();
    const lines = responseText.split(/\r?\n/);
    let breachCount = 0;

    for (const line of lines) {
      const parts = line.split(":");

      if (parts[0] === suffix) {
        breachCount = Number(parts[1]);
        break;
      }
    }

    if (breachCount > 0) {
      const count = breachCount.toLocaleString("en-IN");
      showResult(
        "found",
        "Found in breach data " + count + " times. Do not use this password."
      );
    } else {
      showResult(
        "safe",
        "No match found. This does not guarantee that the password is secure or unique."
      );
    }
  } catch (error) {
    showResult("error", "Could not reach the breach service. Please try again.");
  } finally {
    password = "";
    checkButton.disabled = false;
    checkButton.textContent = "Check password";
  }
});

// Create an uppercase SHA-1 hash with the browser's Web Crypto API.
async function createSha1(password) {
  const bytes = new TextEncoder().encode(password);
  const hashBuffer = await crypto.subtle.digest("SHA-1", bytes);
  bytes.fill(0);

  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray
    .map(function (byte) {
      return byte.toString(16).padStart(2, "0");
    })
    .join("")
    .toUpperCase();
}

clearButton.addEventListener("click", function () {
  passwordInput.value = "";
  passwordInput.type = "password";
  showButton.textContent = "Show";
  updateMeter(0, "Waiting", "Type a password to start the local strength check.");
  hideResult();
  passwordInput.focus();
});

function showResult(type, message) {
  resultBox.className = "result show " + type;
  resultBox.textContent = message;
}

function hideResult() {
  resultBox.className = "result";
  resultBox.textContent = "";
}
