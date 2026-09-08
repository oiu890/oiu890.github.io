document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".cryptic-scribble").forEach((container) => {

    const toggleButton = document.createElement("button");
    toggleButton.textContent = "Open Scribble Space";
    toggleButton.type = "button";
    toggleButton.className = "scribble-toggle";
    container.appendChild(toggleButton);

    const workspace = document.createElement("div");
    workspace.className = "scribble-workspace";
    workspace.hidden = true;

    const board = document.createElement("div");
    board.className = "scribble-board";
    board.tabIndex = 0; // still allow focus/click target

    // ----------------------------
    // Hidden mobile-keyboard trigger
    // ----------------------------
    const mobileInput = document.createElement("input");
    mobileInput.type = "text";
    mobileInput.autocomplete = "off";
    mobileInput.autocapitalize = "characters";
    mobileInput.spellcheck = false;
    mobileInput.className = "scribble-mobile-input";
    // visually hidden but focusable (display:none / opacity:0+pointer-events:none can block focus on iOS)
    mobileInput.setAttribute("aria-hidden", "true");

    const controls = document.createElement("div");
    controls.className = "scribble-controls";

    const shuffleButton = document.createElement("button");
    shuffleButton.textContent = "Shuffle";
    shuffleButton.type = "button";

    const clearButton = document.createElement("button");
    clearButton.textContent = "Clear";
    clearButton.type = "button";

    controls.append(shuffleButton, clearButton);

    board.appendChild(mobileInput);
    workspace.append(board, controls);
    container.appendChild(workspace);

    let isOpen = false;

    function focusMobileInput() {
      // keep it empty so 'input' events always represent a fresh keystroke
      mobileInput.value = "";
      mobileInput.focus({ preventScroll: true });
    }

    toggleButton.addEventListener("click", () => {
      isOpen = !isOpen;
      workspace.hidden = !isOpen;

      if (isOpen) {
        toggleButton.textContent = "Close Scribble Space";
        focusMobileInput();
      } else {
        toggleButton.textContent = "Open Scribble Space";
        mobileInput.blur();
      }
    });

    // Tapping anywhere on the board re-summons the keyboard
    // (mobile browsers only show it on a direct user gesture + focus)
    board.addEventListener("pointerdown", (event) => {
      if (event.target === mobileInput) return;
      focusMobileInput();
    });

    // ============================================================
    // ARRANGE LETTERS (unchanged, but skip the hidden input itself)
    // ============================================================
    function arrangeLetters() {
      const boxes = [...board.children].filter(
        (el) => el !== mobileInput
      );

      if (boxes.length === 0) {
        board.style.height = "220px";
        return;
      }

      const letterWidth = 42;
      const letterHeight = 42;
      const gap = 8;
      const rowGap = 10;
      const availableWidth = board.clientWidth - 20;
      const perRow = Math.max(
        1,
        Math.floor((availableWidth + gap) / (letterWidth + gap))
      );

      const rows = [];
      for (let i = 0; i < boxes.length; i += perRow) {
        rows.push(boxes.slice(i, i + perRow));
      }

      const totalHeight =
        rows.length * letterHeight + (rows.length - 1) * rowGap;
      const boardHeight = Math.max(220, totalHeight + 40);
      board.style.height = `${boardHeight}px`;

      const startY = Math.max(10, (boardHeight - totalHeight) / 2);

      rows.forEach((row, rowIndex) => {
        const rowWidth = row.length * letterWidth + (row.length - 1) * gap;
        const startX = (board.clientWidth - rowWidth) / 2;

        row.forEach((box, index) => {
          box.style.left = `${startX + index * (letterWidth + gap)}px`;
          box.style.top = `${startY + rowIndex * (letterHeight + rowGap)}px`;
        });
      });
    }

    // createLetter(letter) — identical to your existing version, unchanged
    function createLetter(letter) {
      const box = document.createElement("div");
      box.className = "scribble-letter";
      box.textContent = letter;

      let dragging = false;
      let offsetX = 0;
      let offsetY = 0;

      box.addEventListener("pointerdown", (event) => {
        event.stopPropagation(); // don't let board's pointerdown re-steal focus mid-drag
        dragging = true;
        const rect = box.getBoundingClientRect();
        offsetX = event.clientX - rect.left;
        offsetY = event.clientY - rect.top;
        box.setPointerCapture(event.pointerId);
        box.style.zIndex = "10";
        box.style.cursor = "grabbing";
      });

      box.addEventListener("pointermove", (event) => {
        if (!dragging) return;
        const boardRect = board.getBoundingClientRect();
        let x = event.clientX - boardRect.left - offsetX;
        let y = event.clientY - boardRect.top - offsetY;
        x = Math.max(0, Math.min(x, board.clientWidth - box.offsetWidth));
        y = Math.max(0, Math.min(y, board.clientHeight - box.offsetHeight));
        box.style.left = `${x}px`;
        box.style.top = `${y}px`;
      });

      box.addEventListener("pointerup", (event) => {
        dragging = false;
        if (box.hasPointerCapture(event.pointerId)) {
          box.releasePointerCapture(event.pointerId);
        }
        box.style.zIndex = "";
        box.style.cursor = "grab";
      });

      box.addEventListener("pointercancel", () => {
        dragging = false;
        box.style.zIndex = "";
        box.style.cursor = "grab";
      });

      return box;
    }

    // ============================================================
    // KEYBOARD INPUT — desktop path (unchanged, but ignores mobileInput itself)
    // ============================================================
    function handleKeydown(event) {
      if (!isOpen) return;

      if (
        event.target.tagName === "TEXTAREA" ||
        event.target.isContentEditable ||
        (event.target.tagName === "INPUT" && event.target !== mobileInput)
      ) {
        return;
      }

      // If focus is on mobileInput, let 'input'/'beforeinput' handle letters,
      // but still handle Backspace here as a fallback for desktop.
      if (event.target === mobileInput) return;

      if (/^[a-zA-Z]$/.test(event.key)) {
        board.appendChild(createLetter(event.key.toUpperCase()));
        arrangeLetters();
        event.preventDefault();
      }

      if (event.key === "Backspace" && board.children.length > 1) {
        // >1 because mobileInput itself lives in board.children
        removeLastLetter();
        event.preventDefault();
      }
    }

    document.addEventListener("keydown", handleKeydown);

    // ============================================================
    // MOBILE INPUT — 'input' + 'beforeinput' path
    // ============================================================
    function removeLastLetter() {
      const boxes = [...board.children].filter((el) => el !== mobileInput);
      const last = boxes[boxes.length - 1];
      if (last) board.removeChild(last);
      arrangeLetters();
    }

    mobileInput.addEventListener("beforeinput", (event) => {
      if (event.inputType === "deleteContentBackward") {
        event.preventDefault();
        removeLastLetter();
        mobileInput.value = "";
      }
    });

    mobileInput.addEventListener("input", () => {
      const raw = mobileInput.value;
      const letters = raw.replace(/[^a-zA-Z]/g, "");

      for (const ch of letters) {
        board.appendChild(createLetter(ch.toUpperCase()));
      }

      arrangeLetters();
      mobileInput.value = ""; // reset so next input event is a clean keystroke
    });

    // ============================================================
    // SHUFFLE / CLEAR — skip mobileInput
    // ============================================================
    shuffleButton.addEventListener("click", () => {
      const boxes = [...board.children].filter((el) => el !== mobileInput);

      for (let i = boxes.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [boxes[i], boxes[j]] = [boxes[j], boxes[i]];
      }

      boxes.forEach((box) => board.appendChild(box));
      arrangeLetters();
    });

    clearButton.addEventListener("click", () => {
      [...board.children]
        .filter((el) => el !== mobileInput)
        .forEach((el) => board.removeChild(el));
      arrangeLetters();
    });

    window.addEventListener("resize", () => {
      if (isOpen) arrangeLetters();
    });
  });
});
