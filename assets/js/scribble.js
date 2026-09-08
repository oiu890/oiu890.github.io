document.addEventListener("DOMContentLoaded", () => {
  // ============================================================
  // SCRIBBLE SPACES
  // ============================================================

  document.querySelectorAll(".cryptic-scribble").forEach((container) => {

    // ----------------------------
    // Open / Close button
    // ----------------------------

    const toggleButton = document.createElement("button");
    toggleButton.textContent = "Open Scribble Space";
    toggleButton.type = "button";
    toggleButton.className = "scribble-toggle";

    container.appendChild(toggleButton);


    // ----------------------------
    // Scribble area
    // ----------------------------

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

    workspace.append(board, controls);
    container.appendChild(workspace);


    // ============================================================
    // OPEN / CLOSE
    // ============================================================

    let isOpen = false;

    toggleButton.addEventListener("click", () => {
      isOpen = !isOpen;

      workspace.hidden = !isOpen;

      if (isOpen) {
        toggleButton.textContent = "Close Scribble Space";
        board.focus();
      } else {
        toggleButton.textContent = "Open Scribble Space";
      }
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

      const letterWidth = 42;
      const letterHeight = 42;
      const gap = 8;
      const rowGap = 10;

      const availableWidth = board.clientWidth - 20;

      const perRow = Math.max(
        1,
        Math.floor(
          (availableWidth + gap) /
          (letterWidth + gap)
        )
      );

      const rows = [];

      for (let i = 0; i < boxes.length; i += perRow) {
        rows.push(boxes.slice(i, i + perRow));
      }

      const totalHeight =
        rows.length * letterHeight +
        (rows.length - 1) * rowGap;

      // Make the board grow if there are lots of letters
      const boardHeight = Math.max(
        220,
        totalHeight + 40
      );

      board.style.height = `${boardHeight}px`;

      const startY =
        Math.max(
          10,
          (boardHeight - totalHeight) / 2
        );

      rows.forEach((row, rowIndex) => {

        const rowWidth =
          row.length * letterWidth +
          (row.length - 1) * gap;

        const startX =
          (board.clientWidth - rowWidth) / 2;

        row.forEach((box, index) => {

          box.style.left =
            `${startX + index * (letterWidth + gap)}px`;

          box.style.top =
            `${startY + rowIndex * (letterHeight + rowGap)}px`;
        });
      });
    }


    // ============================================================
    // CREATE LETTER
    // ============================================================

    function createLetter(letter) {
      const box = document.createElement("div");

      box.className = "scribble-letter";
      box.textContent = letter;

      let dragging = false;
      let offsetX = 0;
      let offsetY = 0;

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

        const boardRect =
          board.getBoundingClientRect();

        let x =
          event.clientX -
          boardRect.left -
          offsetX;

        let y =
          event.clientY -
          boardRect.top -
          offsetY;

        x = Math.max(
          0,
          Math.min(
            x,
            board.clientWidth - box.offsetWidth
          )
        );

        y = Math.max(
          0,
          Math.min(
            y,
            board.clientHeight - box.offsetHeight
          )
        );

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
    // KEYBOARD INPUT
    // ============================================================

    // IMPORTANT:
    // This listener only exists while the scribble space is open.

    function handleKeydown(event) {

      if (!isOpen) return;

      // Don't steal keyboard input from normal text inputs
      if (
        event.target.tagName === "INPUT" ||
        event.target.tagName === "TEXTAREA" ||
        event.target.isContentEditable
      ) {
        return;
      }

      // Add letters
      if (/^[a-zA-Z]$/.test(event.key)) {

        const letter =
          event.key.toUpperCase();

        board.appendChild(
          createLetter(letter)
        );

        arrangeLetters();

        event.preventDefault();
      }

      // Backspace removes last letter
      if (
        event.key === "Backspace" &&
        board.children.length > 0
      ) {

        board.removeChild(
          board.lastElementChild
        );

        arrangeLetters();

        event.preventDefault();
      }
    }

    document.addEventListener(
      "keydown",
      handleKeydown
    );


    // ============================================================
    // SHUFFLE
    // ============================================================

    shuffleButton.addEventListener("click", () => {

      const boxes = [...board.children];

      for (
        let i = boxes.length - 1;
        i > 0;
        i--
      ) {

        const j =
          Math.floor(
            Math.random() * (i + 1)
          );

        [boxes[i], boxes[j]] =
          [boxes[j], boxes[i]];
      }

      boxes.forEach((box) => {
        board.appendChild(box);
      });

      arrangeLetters();
    });


    // ============================================================
    // CLEAR
    // ============================================================

    clearButton.addEventListener("click", () => {

      board.innerHTML = "";

      arrangeLetters();
    });


    // ============================================================
    // RESIZE
    // ============================================================

    window.addEventListener(
      "resize",
      () => {
        if (isOpen) {
          arrangeLetters();
        }
      }
    );

  });

});
