(function () {
  "use strict";

  const STYLE_ID = "kairos-jodit-codeblock-styles";
  const CODE_ICON_SVG =
    '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: -2px; margin-right: 5px;"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>';

  const BLOCK_TAGS = new Set([
    "P",
    "DIV",
    "PRE",
    "BLOCKQUOTE",
    "LI",
    "UL",
    "OL",
    "H1",
    "H2",
    "H3",
    "H4",
    "H5",
    "H6",
    "TR",
    "TABLE",
    "THEAD",
    "TBODY",
    "TFOOT",
    "SECTION",
    "ARTICLE",
    "HEADER",
    "FOOTER"
  ]);

  function injectStyles() {
    if (document.getElementById(STYLE_ID)) {
      return;
    }
    const style = document.createElement("style");
    style.id = STYLE_ID;
    style.textContent = `
      /* Multi-line <pre><code> styling inside the Jodit dark editor */
      .jodit-wysiwyg pre {
        background-color: #161b22 !important;
        color: #e6edf3 !important;
        border: 1px solid #30363d !important;
        border-left: 3px solid #58a6ff !important;
        border-radius: 6px !important;
        padding: 12px 14px !important;
        margin: 10px 0 !important;
        font-family: SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace !important;
        font-size: 13px !important;
        line-height: 1.5 !important;
        white-space: pre-wrap !important;
        word-wrap: break-word !important;
        overflow-wrap: break-word !important;
        tab-size: 4 !important;
      }

      .jodit-wysiwyg pre code {
        background: transparent !important;
        color: inherit !important;
        padding: 0 !important;
        margin: 0 !important;
        border: none !important;
        border-radius: 0 !important;
        font-family: inherit !important;
        font-size: inherit !important;
        line-height: inherit !important;
        white-space: pre-wrap !important;
        word-wrap: break-word !important;
        display: block !important;
      }

      .jodit-wysiwyg code {
        background-color: rgba(110, 118, 129, 0.35);
        color: #e6edf3;
        padding: 2px 5px;
        border-radius: 4px;
        font-family: SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
        font-size: 88%;
      }

      /* Toolbar Code Block button */
      .jodit-toolbar-button_codeBlock button.jodit-toolbar-button__button {
        width: auto !important;
        padding: 0 8px !important;
      }

      .kairos-tb-codeblock {
        display: inline-flex;
        align-items: center;
        font-size: 12px;
        font-weight: 600;
        color: #58a6ff;
        white-space: nowrap;
        line-height: 1;
      }

      .jodit-toolbar-button_codeBlock[aria-pressed="true"] .kairos-tb-codeblock,
      .jodit-toolbar-button_codeBlock button[aria-pressed="true"] .kairos-tb-codeblock {
        color: #ffffff;
      }

      /* Footer bar at the bottom of the editor */
      .kairos-editor-footer {
        display: flex;
        align-items: center;
        justify-content: space-between;
        flex-wrap: wrap;
        gap: 8px;
        background-color: #161b22;
        border-top: 1px solid #30363d;
        padding: 6px 10px;
        color: #8b949e;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        font-size: 12px;
        user-select: none;
      }

      .kairos-footer-actions {
        display: flex;
        align-items: center;
        gap: 8px;
      }

      .kairos-footer-code-btn {
        display: inline-flex;
        align-items: center;
        background-color: #21262d;
        color: #58a6ff;
        border: 1px solid #30363d;
        border-radius: 5px;
        padding: 4px 10px;
        font-size: 12px;
        font-weight: 600;
        line-height: 1.3;
        cursor: pointer;
        transition: background-color 0.15s ease, border-color 0.15s ease, color 0.15s ease;
      }

      .kairos-footer-code-btn:hover {
        background-color: #30363d;
        border-color: #58a6ff;
        color: #79c0ff;
      }

      .kairos-footer-code-btn.is-active {
        background-color: #1f6feb;
        border-color: #388bfd;
        color: #ffffff;
      }

      .kairos-footer-hint {
        color: #8b949e;
        font-size: 11.5px;
      }
    `;
    document.head.appendChild(style);
  }

  function closestTag(node, tagName, root) {
    let cur = node;
    const upper = tagName.toUpperCase();
    while (cur && cur !== root && cur !== document) {
      if (cur.nodeType === 1 && cur.tagName === upper) {
        return cur;
      }
      cur = cur.parentNode;
    }
    return null;
  }

  function hasBlockChild(el) {
    if (!el || !el.children) {
      return false;
    }
    for (let i = 0; i < el.children.length; i += 1) {
      if (BLOCK_TAGS.has(el.children[i].tagName)) {
        return true;
      }
    }
    return false;
  }

  function hasMeaningfulSiblingAfter(brNode, stopAncestor) {
    let cur = brNode;
    while (cur && cur !== stopAncestor) {
      let sib = cur.nextSibling;
      while (sib) {
        if (sib.nodeType === 3) {
          if (sib.nodeValue && sib.nodeValue.length > 0) {
            return true;
          }
        } else if (sib.nodeType === 1) {
          if (sib.tagName === "BR") {
            return true;
          }
          if (sib.textContent && sib.textContent.length > 0) {
            return true;
          }
        }
        sib = sib.nextSibling;
      }
      cur = cur.parentNode;
    }
    return false;
  }

  function extractInlineText(nodes, containerAncestor) {
    let out = "";
    function walk(nodeList) {
      for (let i = 0; i < nodeList.length; i += 1) {
        const n = nodeList[i];
        if (n.nodeType === 3) {
          out += n.nodeValue.replace(/\r\n?/g, "\n").replace(/\u00a0/g, " ");
        } else if (n.nodeType === 1) {
          if (n.tagName === "BR") {
            if (hasMeaningfulSiblingAfter(n, containerAncestor)) {
              out += "\n";
            }
          } else {
            walk(n.childNodes);
          }
        }
      }
    }
    walk(nodes);
    return out;
  }

  function extractCodeTextFromFragment(fragment) {
    const lines = [];
    let inlineRun = [];

    function flushInlineRun() {
      if (inlineRun.length === 0) {
        return;
      }
      const wrapper = document.createElement("span");
      for (let i = 0; i < inlineRun.length; i += 1) {
        wrapper.appendChild(inlineRun[i].cloneNode(true));
      }
      const text = extractInlineText(wrapper.childNodes, wrapper);
      if (text.length > 0 || inlineRun.some((n) => n.nodeType === 1 && n.tagName === "BR")) {
        lines.push(text);
      }
      inlineRun = [];
    }

    function walkContainer(container) {
      const children = container.childNodes;
      for (let i = 0; i < children.length; i += 1) {
        const child = children[i];
        if (child.nodeType === 1 && BLOCK_TAGS.has(child.tagName)) {
          flushInlineRun();
          if (hasBlockChild(child)) {
            walkContainer(child);
          } else {
            const text = extractInlineText(child.childNodes, child);
            lines.push(text);
          }
        } else {
          inlineRun.push(child);
        }
      }
      flushInlineRun();
    }

    walkContainer(fragment);
    return lines.join("\n").replace(/^\n+|\n+$/g, "");
  }

  function isBlockVisuallyEmpty(el) {
    if (!el || el.nodeType !== 1) {
      return true;
    }
    if (el.querySelector("img, table, hr, iframe, pre")) {
      return false;
    }
    const text = (el.textContent || "").replace(/\u200b/g, "");
    return text.length === 0;
  }

  function trimLeadingTrailingBr(el) {
    if (!el) {
      return;
    }
    while (el.firstChild && el.firstChild.nodeType === 1 && el.firstChild.tagName === "BR") {
      el.removeChild(el.firstChild);
    }
    while (el.lastChild && el.lastChild.nodeType === 1 && el.lastChild.tagName === "BR") {
      el.removeChild(el.lastChild);
    }
  }

  function getSelectionPre(jodit) {
    if (!jodit || !jodit.ed || !jodit.editor) {
      return null;
    }
    const sel = jodit.ew.getSelection();
    if (!sel || sel.rangeCount === 0) {
      return null;
    }
    const range = sel.getRangeAt(0);
    if (!jodit.editor.contains(range.commonAncestorContainer)) {
      return null;
    }
    const startPre = closestTag(range.startContainer, "PRE", jodit.editor);
    const endPre = closestTag(range.endContainer, "PRE", jodit.editor);
    if (startPre && startPre === endPre) {
      return startPre;
    }
    return null;
  }

  function lineToParagraphHtml(line) {
    if (!line || line.length === 0) {
      return "<br>";
    }
    const escaped = line
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/\t/g, "    ");
    return escaped.replace(/^( +)/, function (m) {
      return "&nbsp;".repeat(m.length);
    }).replace(/  /g, " &nbsp;");
  }

  function unwrapPreBlock(jodit, preEl) {
    const doc = jodit.ed;
    const rawText = extractInlineText(preEl.childNodes, preEl);
    const lines = rawText.split("\n");
    const frag = doc.createDocumentFragment();
    let firstP = null;
    let lastP = null;

    for (let i = 0; i < lines.length; i += 1) {
      const p = doc.createElement("p");
      p.innerHTML = lineToParagraphHtml(lines[i]);
      if (!firstP) {
        firstP = p;
      }
      lastP = p;
      frag.appendChild(p);
    }

    const parent = preEl.parentNode;
    if (parent) {
      parent.replaceChild(frag, preEl);
      if (firstP && lastP) {
        const sel = jodit.ew.getSelection();
        const newRange = doc.createRange();
        newRange.setStartBefore(firstP);
        newRange.setEndAfter(lastP);
        sel.removeAllRanges();
        sel.addRange(newRange);
      }
    }
  }

  function syncEditorToStreamlit(jodit) {
    if (!jodit) {
      return;
    }
    try {
      jodit.synchronizeValues();
      jodit.e.fire("change", jodit.value);
      jodit.e.fire("blur");
      updateFooterState(jodit);
      window.dispatchEvent(new Event("resize"));
    } catch (err) {
      // Ignore transient errors during editor teardown
    }
  }

  function toggleCodeBlock(jodit) {
    if (!jodit || !jodit.editor) {
      return;
    }

    const doc = jodit.ed;
    const sel = jodit.ew.getSelection();

    // Restore saved selection if editor lost selection momentarily
    if (
      (!sel || sel.rangeCount === 0 || !jodit.editor.contains(sel.anchorNode)) &&
      jodit.__kairosSavedRange
    ) {
      sel.removeAllRanges();
      sel.addRange(jodit.__kairosSavedRange);
    }

    if (!sel || sel.rangeCount === 0) {
      jodit.s.focus();
    }

    // 1. If cursor/selection is already inside a single <pre> block, unwrap it back to paragraphs
    const existingPre = getSelectionPre(jodit);
    if (existingPre) {
      unwrapPreBlock(jodit, existingPre);
      syncEditorToStreamlit(jodit);
      return;
    }

    const range = sel && sel.rangeCount > 0 ? sel.getRangeAt(0) : null;

    // 2. If nothing is highlighted, insert a new empty <pre><code> block and place cursor inside
    if (!range || range.collapsed || !jodit.editor.contains(range.commonAncestorContainer)) {
      const pre = doc.createElement("pre");
      const code = doc.createElement("code");
      code.textContent = "\n";
      pre.appendChild(code);

      if (range && jodit.editor.contains(range.commonAncestorContainer)) {
        const parentP = closestTag(range.startContainer, "P", jodit.editor);
        if (parentP && isBlockVisuallyEmpty(parentP)) {
          parentP.parentNode.replaceChild(pre, parentP);
        } else if (parentP) {
          parentP.parentNode.insertBefore(pre, parentP.nextSibling);
        } else {
          range.insertNode(pre);
        }
      } else {
        jodit.editor.appendChild(pre);
      }

      if (!pre.nextElementSibling) {
        const trailingP = doc.createElement("p");
        trailingP.innerHTML = "<br>";
        pre.parentNode.appendChild(trailingP);
      }

      const caretRange = doc.createRange();
      caretRange.setStart(code.firstChild || code, 0);
      caretRange.collapse(true);
      sel.removeAllRanges();
      sel.addRange(caretRange);
      syncEditorToStreamlit(jodit);
      return;
    }

    // 3. Extract multi-line code text from the highlighted selection with spacing preserved
    const cloned = range.cloneContents();
    let codeText = extractCodeTextFromFragment(cloned);
    if (!codeText) {
      codeText = sel.toString().replace(/\r\n?/g, "\n").replace(/\u00a0/g, " ");
    }

    const pre = doc.createElement("pre");
    const code = doc.createElement("code");
    code.textContent = codeText;
    pre.appendChild(code);

    // Track start and end blocks prior to deleting range contents
    const startBlock =
      closestTag(range.startContainer, "P", jodit.editor) ||
      closestTag(range.startContainer, "DIV", jodit.editor) ||
      closestTag(range.startContainer, "PRE", jodit.editor);
    const endBlock =
      closestTag(range.endContainer, "P", jodit.editor) ||
      closestTag(range.endContainer, "DIV", jodit.editor) ||
      closestTag(range.endContainer, "PRE", jodit.editor);

    range.deleteContents();

    const parentP = closestTag(range.startContainer, "P", jodit.editor);
    if (parentP) {
      if (isBlockVisuallyEmpty(parentP)) {
        parentP.parentNode.replaceChild(pre, parentP);
      } else {
        const afterRange = doc.createRange();
        afterRange.setStart(range.startContainer, range.startOffset);
        afterRange.setEndAfter(parentP.lastChild || parentP);
        const afterFrag = afterRange.extractContents();

        trimLeadingTrailingBr(parentP);

        if (isBlockVisuallyEmpty(parentP)) {
          parentP.parentNode.replaceChild(pre, parentP);
        } else {
          parentP.parentNode.insertBefore(pre, parentP.nextSibling);
        }

        const tempDiv = doc.createElement("div");
        tempDiv.appendChild(afterFrag);
        trimLeadingTrailingBr(tempDiv);
        if (!isBlockVisuallyEmpty(tempDiv)) {
          const afterP = doc.createElement("p");
          while (tempDiv.firstChild) {
            afterP.appendChild(tempDiv.firstChild);
          }
          pre.parentNode.insertBefore(afterP, pre.nextSibling);
        }
      }
    } else {
      // Selection inside LI, DIV, or directly in editor root
      const prevNode =
        range.startContainer.nodeType === 1
          ? range.startContainer.childNodes[range.startOffset - 1]
          : range.startContainer.previousSibling;
      if (prevNode && prevNode.nodeType === 1 && prevNode.tagName === "BR") {
        prevNode.remove();
      }
      range.insertNode(pre);
    }

    // Clean up any leftover empty start/end blocks
    if (startBlock && startBlock !== pre && startBlock.parentNode && isBlockVisuallyEmpty(startBlock)) {
      startBlock.remove();
    }
    if (endBlock && endBlock !== pre && endBlock.parentNode && isBlockVisuallyEmpty(endBlock)) {
      endBlock.remove();
    }

    // Ensure there is always a paragraph after the <pre> block so the user can continue typing below it
    if (!pre.nextElementSibling) {
      const nextP = doc.createElement("p");
      nextP.innerHTML = "<br>";
      pre.parentNode.appendChild(nextP);
    }

    // Select the newly created code block content
    const newRange = doc.createRange();
    newRange.selectNodeContents(code);
    sel.removeAllRanges();
    sel.addRange(newRange);
    jodit.__kairosSavedRange = newRange.cloneRange();

    syncEditorToStreamlit(jodit);
  }

  function updateFooterState(jodit) {
    if (!jodit || !jodit.__kairosFooterBtn) {
      return;
    }
    const inPre = Boolean(getSelectionPre(jodit));
    const btn = jodit.__kairosFooterBtn;
    if (inPre) {
      btn.classList.add("is-active");
      btn.innerHTML = CODE_ICON_SVG + "<span>Unwrap Code Block</span>";
    } else {
      btn.classList.remove("is-active");
      btn.innerHTML = CODE_ICON_SVG + "<span>Format Selection as Code Block</span>";
    }
  }

  function attachEditorListeners(jodit) {
    if (!jodit || !jodit.editor) {
      return;
    }

    const saveSelection = function () {
      try {
        const sel = jodit.ew.getSelection();
        if (sel && sel.rangeCount > 0) {
          const r = sel.getRangeAt(0);
          if (jodit.editor.contains(r.commonAncestorContainer)) {
            if (!r.collapsed) {
              jodit.__kairosSavedRange = r.cloneRange();
            }
            updateFooterState(jodit);
          }
        }
      } catch (err) {
        // Ignore selection errors
      }
    };

    jodit.editor.addEventListener("mouseup", saveSelection);
    jodit.editor.addEventListener("keyup", saveSelection);
    jodit.ed.addEventListener("selectionchange", saveSelection);

    // Handle Tab, Ctrl+Shift+M, and ArrowDown inside <pre><code>
    jodit.editor.addEventListener(
      "keydown",
      function (e) {
        if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === "M" || e.key === "m")) {
          e.preventDefault();
          e.stopPropagation();
          toggleCodeBlock(jodit);
          return;
        }

        const pre = getSelectionPre(jodit);
        if (!pre) {
          return;
        }

        if (e.key === "Tab") {
          e.preventDefault();
          e.stopPropagation();
          const sel = jodit.ew.getSelection();
          if (!sel || sel.rangeCount === 0) {
            return;
          }
          const range = sel.getRangeAt(0);
          range.deleteContents();
          const tabNode = jodit.ed.createTextNode("    ");
          range.insertNode(tabNode);
          range.setStartAfter(tabNode);
          range.setEndAfter(tabNode);
          sel.removeAllRanges();
          sel.addRange(range);
          syncEditorToStreamlit(jodit);
        } else if (e.key === "ArrowDown" && !e.shiftKey) {
          const sel = jodit.ew.getSelection();
          if (sel && sel.rangeCount > 0) {
            const range = sel.getRangeAt(0);
            const afterRange = jodit.ed.createRange();
            afterRange.setStart(range.endContainer, range.endOffset);
            afterRange.setEndAfter(pre.lastChild || pre);
            const remaining = afterRange.toString();
            if (!remaining.includes("\n") && !pre.nextElementSibling) {
              const nextP = jodit.ed.createElement("p");
              nextP.innerHTML = "<br>";
              pre.parentNode.appendChild(nextP);
            }
          }
        }
      },
      true
    );

    // Clean paste handling inside <pre> (inserts raw plain text with newlines & indentation)
    jodit.editor.addEventListener(
      "paste",
      function (e) {
        const pre = getSelectionPre(jodit);
        if (!pre) {
          return;
        }
        const cd = e.clipboardData;
        if (!cd) {
          return;
        }
        // Let image pastes go through to Jodit's image uploader
        if (cd.files && cd.files.length > 0) {
          return;
        }
        const plain = cd.getData("text/plain");
        if (!plain) {
          return;
        }
        e.preventDefault();
        e.stopPropagation();

        let targetCode = closestTag(
          jodit.ew.getSelection().anchorNode,
          "CODE",
          pre
        );
        if (!targetCode) {
          targetCode = pre.querySelector("code");
          if (!targetCode) {
            targetCode = jodit.ed.createElement("code");
            while (pre.firstChild) {
              targetCode.appendChild(pre.firstChild);
            }
            pre.appendChild(targetCode);
          }
        }

        const normalized = plain.replace(/\r\n?/g, "\n").replace(/\t/g, "    ");
        const sel = jodit.ew.getSelection();
        if (sel && sel.rangeCount > 0) {
          const range = sel.getRangeAt(0);
          range.deleteContents();
          const textNode = jodit.ed.createTextNode(normalized);
          range.insertNode(textNode);
          range.setStartAfter(textNode);
          range.setEndAfter(textNode);
          sel.removeAllRanges();
          sel.addRange(range);
        }
        syncEditorToStreamlit(jodit);
      },
      true
    );

    // Preserve leading spaces & tabs when pasting plain text into normal paragraphs
    // so indentation is not lost before the user highlights and clicks Code Block
    jodit.e.on("processPaste.kairosCodeBlock", function (event, text, type) {
      if (typeof text === "string" && type === "text/plain;" && !/<[a-z][\s\S]*>/i.test(text)) {
        const lines = text.replace(/\r\n?/g, "\n").split("\n");
        if (lines.some((l) => /^[ \t]+/.test(l))) {
          return lines
            .map(function (line) {
              const expanded = line.replace(/\t/g, "    ");
              return expanded.replace(/^( +)/, function (m) {
                return "&nbsp;".repeat(m.length);
              });
            })
            .join("<br>");
        }
      }
      return undefined;
    });
  }

  function enhanceJoditInstance(jodit) {
    if (!jodit || jodit.__kairosCodeBlockInstalled) {
      return;
    }
    jodit.__kairosCodeBlockInstalled = true;

    injectStyles();

    const setup = function () {
      try {
        // 1. Register the toolbar button control
        jodit.o.controls = jodit.o.controls || {};
        jodit.o.controls.codeBlock = {
          name: "codeBlock",
          tooltip: "Format highlighted text as multi-line Code Block (Ctrl+Shift+M)",
          template: function () {
            return (
              '<span class="kairos-tb-codeblock">' +
              CODE_ICON_SVG +
              "<span>Code Block</span></span>"
            );
          },
          isActive: function (editor) {
            return Boolean(getSelectionPre(editor));
          },
          exec: function (editor) {
            toggleCodeBlock(editor);
          }
        };

        const extra = Array.isArray(jodit.o.extraButtons)
          ? jodit.o.extraButtons.slice()
          : [];
        if (!extra.some((b) => b === "codeBlock" || (b && b.name === "codeBlock"))) {
          extra.push("codeBlock");
          jodit.o.extraButtons = extra;
        }

        if (typeof jodit.buildToolbar === "function") {
          jodit.buildToolbar();
        }

        // 2. Add the Footer Bar with the Code Block button at the bottom of .jodit-container
        if (jodit.container && !jodit.container.querySelector(".kairos-editor-footer")) {
          const footer = document.createElement("div");
          footer.className = "kairos-editor-footer";

          const actions = document.createElement("div");
          actions.className = "kairos-footer-actions";

          const btn = document.createElement("button");
          btn.type = "button";
          btn.className = "kairos-footer-code-btn";
          btn.title = "Wrap highlighted lines in <pre><code> and preserve spacing (Ctrl+Shift+M)";
          btn.innerHTML = CODE_ICON_SVG + "<span>Format Selection as Code Block</span>";

          // Prevent mousedown from stealing focus/selection from the editor
          btn.addEventListener("mousedown", function (e) {
            e.preventDefault();
          });
          btn.addEventListener("click", function (e) {
            e.preventDefault();
            toggleCodeBlock(jodit);
          });

          jodit.__kairosFooterBtn = btn;
          actions.appendChild(btn);

          const hint = document.createElement("span");
          hint.className = "kairos-footer-hint";
          hint.textContent =
            "Tip: Highlight multi-line code and click the button (or press Ctrl+Shift+M) to format as a code block.";

          footer.appendChild(actions);
          footer.appendChild(hint);
          jodit.container.appendChild(footer);
        }

        attachEditorListeners(jodit);
        window.dispatchEvent(new Event("resize"));
      } catch (err) {
        console.error("Kairos CodeBlock init error:", err);
      }
    };

    if (jodit.isReady) {
      setup();
    } else if (typeof jodit.waitForReady === "function") {
      jodit.waitForReady().then(setup);
    } else {
      setTimeout(setup, 50);
    }
  }

  function scanForEditors() {
    const textareas = document.querySelectorAll(".jodit-react-container textarea, textarea");
    for (let i = 0; i < textareas.length; i += 1) {
      const ta = textareas[i];
      if (ta && ta.component && ta.component.isJodit) {
        enhanceJoditInstance(ta.component);
      }
    }
  }

  function initObserver() {
    injectStyles();
    scanForEditors();

    const observer = new MutationObserver(function () {
      scanForEditors();
    });

    if (document.body) {
      observer.observe(document.body, { childList: true, subtree: true });
    } else {
      window.addEventListener("DOMContentLoaded", function () {
        scanForEditors();
        observer.observe(document.body, { childList: true, subtree: true });
      });
    }

    // Periodic check for the first 3 seconds to catch fast React mounts
    let checks = 0;
    const timer = setInterval(function () {
      scanForEditors();
      checks += 1;
      if (checks > 30) {
        clearInterval(timer);
      }
    }, 100);
  }

  if (typeof window !== "undefined" && typeof document !== "undefined") {
    initObserver();
  }
})();
