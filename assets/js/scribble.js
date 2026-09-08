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

    const controls = document.createElement("div");
    controls.className = "scribble-controls";

    const shuffleButton = document.createElement("button");
    shuffleButton.textContent = "Shuffle";
    shuffleButton.type = "button";

    const clearButton = document.createElement("button");
    clearButton.textContent = "Clear";
    clearButton.type = "button";

    controls.append(shuffleButton, clearButton);

    // ----------------------------
    // On-screen keyboard
    // ----------------------------
    const keyboard = document.createElement("div");
    keyboard.className = "scribble-keyboard";

    const rows = ["QWERTYUIOP", "ASDFGHJKL", "ZXCVBNM"];

    rows.forEach((row, i) => {
      const rowEl = document.createElement("div");
      rowEl.className = "scribble-key-row";

      if (i === 2) {
        [...row].forEach((letter) => {
          const key = document.createElement("button");
          key.type = "button";
          key.className = "scribble-key";
          key.textContent = letter;
          key.addEventListener("click", () => {
            board.appendChild(createLetter(letter));
            arrangeLetters();
          });
          rowEl.appendChild(key);
        });

        const back = document.createElement("button");
        back.type = "button";
        back.className = "scribble-key scribble-key-wide";
        back.textContent = "⌫";
        back.addEventListener("click", () => removeLastLetter());
        rowEl.appendChild(back);
      } else {
        [...row].forEach((letter) => {
          const key = document.createElement("button");
          key.type = "button";
          key.className = "scribble-key";
          key.textContent = letter;
          key.addEventListener("click", () => {
            board.appendChild(createLetter(letter));
            arrangeLetters();
          });
          rowEl.appendChild(key);
        });
      }

      keyboard.appendChild(rowEl);
    });

    workspace.append(board, keyboard, controls);
    container.appendChild(workspace);

    let isOpen = false;

    toggleButton.addEventListener("click", () => {
      isOpen = !isOpen;
      workspace.hidden = !isOpen;
      toggleButton.textContent = isOpen
        ? "Close Scribble Space"
        : "Open Scribble Space";
    });

    // ============================================================
    // ARRANGE LETTERS
    // ============================================================
    function arrangeLetters() {
      const boxes = [...board.children];
      if (boxes.length === 0) {
        board.style.height = "220px";
        return;
      }

      const letterWidth = 42, letterHeight = 42, gap = 8, rowGap = 10;
      const availableWidth = board.clientWidth - 20;
      const perRow = Math.max(1, Math.floor((availableWidth + gap) / (letterWidth + gap)));

      const rowsArr = [];
      for (let i = 0; i < boxes.length; i += perRow) {
        rowsArr.push(boxes.slice(i, i + perRow));
      }

      const totalHeight = rowsArr.length * letterHeight + (rowsArr.length - 1) * rowGap;
      const boardHeight = Math.max(220, totalHeight + 40);
      board.style.height = `${boardHeight}px`;

      const startY = Math.max(10, (boardHeight - totalHeight) / 2);

      rowsArr.forEach((row, rowIndex) => {
        const rowWidth = row.length * letterWidth + (row.length - 1) * gap;
        const startX = (board.clientWidth - rowWidth) / 2;
        row.forEach((box, index) => {
          box.style.left = `${startX + index * (letterWidth + gap)}px`;
          box.style.top = `${startY + rowIndex * (letterHeight + rowGap)}px`;
        });
      });
    }

    // ============================================================
    // CREATE LETTER (draggable box)
    // ============================================================
    function createLetter(letter) {
      const box = document.createElement("div");
      box.className = "scribble-letter";
      box.textContent = letter;

      let dragging = false, offsetX = 0, offsetY = 0;

      box.addEventListener("pointerdown", (event) => {
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
        if (box.hasPointerCapture(event.pointerId)) box.releasePointerCapture(event.pointerId);
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

    function removeLastLetter() {
      if (board.children.length > 0) {
        board.removeChild(board.lastElementChild);
        arrangeLetters();
      }
    }

    // ============================================================
    // PHYSICAL KEYBOARD — still works for desktop users
    // ============================================================
    function handleKeydown(event) {
      if (!isOpen) return;

      if (
        event.target.tagName === "INPUT" ||
        event.target.tagName === "TEXTAREA" ||
        event.target.isContentEditable
      ) return;

      if (/^[a-zA-Z]$/.test(event.key)) {
        board.appendChild(createLetter(event.key.toUpperCase()));
        arrangeLetters();
        event.preventDefault();
      }

      if (event.key === "Backspace") {
        removeLastLetter();
        event.preventDefault();
      }
    }

    document.addEventListener("keydown", handleKeydown);

    // ============================================================
    // SHUFFLE / CLEAR
    // ============================================================
    shuffleButton.addEventListener("click", () => {
      const boxes = [...board.children];
      for (let i = boxes.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [boxes[i], boxes[j]] = [boxes[j], boxes[i]];
      }
      boxes.forEach((box) => board.appendChild(box));
      arrangeLetters();
    });

    clearButton.addEventListener("click", () => {
      board.innerHTML = "";
      arrangeLetters();
    });

    // ============================================================
    // RESIZE
    // ============================================================
    window.addEventListener("resize", () => {
      if (isOpen) arrangeLetters();
    });
  });
});
