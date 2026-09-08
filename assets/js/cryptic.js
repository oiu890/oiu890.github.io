document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".cryptic-input").forEach((container) => {
    const answer = container.dataset.answer.toUpperCase();

    // Container for the letter boxes
    const boxes = document.createElement("div");
    boxes.className = "cryptic-boxes";

    // Create one input box per letter
    for (let i = 0; i < answer.length; i++) {
      const input = document.createElement("input");

      input.type = "text";
      input.maxLength = 1;
      input.className = "cryptic-letter";
      input.autocomplete = "off";
      input.setAttribute("aria-label", `Letter ${i + 1}`);

      // Only allow letters + automatically uppercase
      input.addEventListener("input", () => {
        input.value = input.value
          .replace(/[^a-z]/gi, "")
          .toUpperCase();

        // Move to next box
        if (input.value && i < answer.length - 1) {
          boxes.children[i + 1].focus();
        }
      });

      // Backspace goes to previous box
      input.addEventListener("keydown", (event) => {
        if (
          event.key === "Backspace" &&
          input.value === "" &&
          i > 0
        ) {
          boxes.children[i - 1].focus();
        }

        // Enter checks the answer
        if (event.key === "Enter") {
          checkAnswer();
        }
      });

      boxes.appendChild(input);
    }

    // Check button
    const button = document.createElement("button");
    button.textContent = "Check";
    button.type = "button";
    button.className = "cryptic-check";

    // Result text
    const result = document.createElement("span");
    result.className = "cryptic-result";

    function checkAnswer() {
      const guess = [...boxes.children]
        .map((input) => input.value)
        .join("")
        .toUpperCase();

      if (guess.length !== answer.length) {
        result.textContent = `Enter all ${answer.length} letters.`;
        result.className = "cryptic-result wrong";
        return;
      }

      if (guess === answer) {
        result.textContent = "✓ Correct!";
        result.className = "cryptic-result correct";
      } else {
        result.textContent = "✗ Not quite!";
        result.className = "cryptic-result wrong";
      }
    }

    button.addEventListener("click", checkAnswer);

    // Put everything into the original div
    container.appendChild(boxes);
    container.appendChild(button);
    container.appendChild(result);
  });
});


