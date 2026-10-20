SEMANTIC_WALKER = r"""(options, limits) => {
  const visible = (node) => {
    if (node.closest && node.closest('[hidden],[aria-hidden="true"]')) return false;
    if (typeof node.checkVisibility === 'function'
      && !node.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true })) return false;
    const style = getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || Number(style.opacity) === 0) return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  };
  const clean = (value, cap = 240) => String(value || '').replace(/\s+/g, ' ').trim().slice(0, cap);
  // Shape only — NEVER a second redaction policy. `sanitize::redact_diagnostic`
  // is the canonical gate (d29-one-gate-per-law) and runs over every field this
  // produces: title, page_hint, visible_text, text_blocks, and each element's
  // label/name/placeholder. It redacts `key=value` assignments, secret header
  // labels, and `Bearer <token>` — not the bare prose word. A blacklist here
  // reimplemented that law wrongly and destroyed the page instead: MDN's own
  // "Using HTTP Cookies" rendered as "Using HTTP [REDACTED]", which cost the
  // consumer every page about cookies, sessions, tokens, and authentication —
  // precisely the documentation an agent most often has to read.
  const diagnostic = (value, cap = 240) => {
    const s = String(value || '').replace(/\s+/g, ' ').trim();
    return s.length > cap ? s.slice(0, cap) + ' … [truncated]' : s;
  };
  const safeOrigin = (value) => {
    try {
      const url = new URL(String(value), location.href);
      return clean(`${url.protocol}//${url.host}/`, 512);
    } catch (_) {
      return '[invalid-url]';
    }
  };
  const safeFormAction = (value) => {
    try {
      const baseUri = (document && document.baseURI) ? document.baseURI : location.href;
      const url = new URL(String(value || ''), baseUri);
      const locUrl = new URL(location.href);
      if (url.origin === locUrl.origin && url.origin === new URL(baseUri).origin) {
        return clean(url.pathname + (url.search ? url.search : ''), 512);
      }
      return clean(url.origin + url.pathname + (url.search ? url.search : ''), 512);
    } catch (_) {
      return '[invalid-url]';
    }
  };
  const safeMethod = (value) => {
    const method = String(value || 'get').toLowerCase();
    return ['get', 'post', 'dialog'].includes(method) ? method : 'unknown';
  };
  const safeInputType = (value) => {
    const inputType = String(value || '').toLowerCase();
    return ['button','checkbox','color','date','datetime-local','email','file','hidden','image','month','number','password','radio','range','reset','search','submit','tel','text','time','url','week'].includes(inputType) ? inputType : 'other';
  };
  // A CSS path that actually resolves back to this node.
  //
  // Element.id is positional and was never written to the DOM — its doc comment
  // says `data-nbrowser-id` and nothing has ever set that attribute — so a caller
  // reading a snapshot had an id it could not act on and had to GUESS a
  // selector from the label. On zeit.de the consent button's label comes from
  // aria-label, so the obvious `button[title="Agree and continue"]` matches
  // nothing and the click fails with a bare invalid_input.
  //
  // Computed rather than stamped: writing an attribute would be a DOM mutation
  // inside `snapshot`, which is an observation-ring verb, and the ring boundary
  // is a type boundary here rather than a convention. Prefer a stable id, then
  // a unique attribute, then an nth-of-type chain.
  const isSecretToken = (val) => {
    if (!val) return false;
    let s = String(val).toLowerCase().trim();
    const unquoteLenient = (str) => {
      return String(str).replace(/%([0-9a-fA-F]{2})/g, (_, hex) => {
        try {
          return String.fromCharCode(parseInt(hex, 16));
        } catch (_) {
          return _;
        }
      });
    };
    let cur = s;
    let reachedFixedPoint = false;
    for (let pass = 0; pass < 8; pass += 1) {
      const nxt = unquoteLenient(cur).toLowerCase().trim();
      if (nxt === cur) {
        reachedFixedPoint = true;
        break;
      }
      cur = nxt;
    }
    if (!reachedFixedPoint) return true;
    if (/(?:(?:sk|ghp|gho|ghu|ghs|ghr|github_pat|github|glpat|xoxb|xoxp|xoxr|npm|live|test|sec|secret|key|token|pat)[-_][0-9a-zA-Z]+|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})/i.test(cur)) return true;
    if (/(?:password|passwd|pwd|pass|pw|senha|secret|apikey|api_key|access_token|refresh_token|authorization|auth|otp|totp|passphrase)/i.test(cur)) return true;
    if (/(?:(?:sk|ghp|gho|ghu|ghs|ghr|github_pat|github|glpat|xoxb|xoxp|xoxr|npm|live|test|sec|secret|key|token|pat)[-_][0-9a-zA-Z]+|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})/i.test(s)) return true;
    if (/(?:password|passwd|pwd|pass|pw|senha|secret|apikey|api_key|access_token|refresh_token|authorization|auth|otp|totp|passphrase)/i.test(s)) return true;
    return false;
  };
  const cssEscape = (value) => (window.CSS && CSS.escape ? CSS.escape(value) : String(value).replace(/[^a-zA-Z0-9_-]/g, '\\$&'));
  const cssPath = (node) => {
    try {
      if (node.id && !isSecretToken(node.id) && document.querySelectorAll('#' + cssEscape(node.id)).length === 1) {
        return '#' + cssEscape(node.id);
      }
      for (const attribute of ['data-testid', 'data-test-id', 'name', 'aria-label']) {
        const value = node.getAttribute && node.getAttribute(attribute);
        if (!value || isSecretToken(value)) continue;
        const candidate = node.tagName.toLowerCase() + '[' + attribute + '="' + String(value).replace(/["\\]/g, '\\$&') + '"]';
        if (document.querySelectorAll(candidate).length === 1) return candidate;
      }
      const parts = [];
      let current = node;
      while (current && current.nodeType === 1 && parts.length < 12) {
        const tag = current.tagName.toLowerCase();
        if (tag === 'html' || tag === 'body') { parts.unshift(tag); break; }
        let rank = 1;
        let sibling = current.previousElementSibling;
        while (sibling) {
          if (sibling.tagName === current.tagName) rank += 1;
          sibling = sibling.previousElementSibling;
        }
        parts.unshift(tag + ':nth-of-type(' + rank + ')');
        current = current.parentElement;
      }
      const path = parts.join(' > ');
      return path && document.querySelector(path) === node ? path : null;
    } catch (e) {
      return null;
    }
  };

  const formNodes = document.forms;
  const forms = [];
  const formIndexes = new Map();
  let visibleFormCount = 0;
  for (let index = 0; index < formNodes.length; index += 1) {
    const form = formNodes[index];
    formIndexes.set(form, index);
    if (index >= limits.form) continue;
    const shown = visible(form);
    if (!options.include_hidden && !shown) continue;
    if (shown) visibleFormCount += 1;
    forms.push({
      index,
      action: safeFormAction(form.getAttribute('action') || location.href),
      method: safeMethod(form.getAttribute('method')),
      id: form.hasAttribute('id') ? '[present]' : null,
      name: form.hasAttribute('name') ? '[present]' : null
    });
  }
  const docGenSym = Symbol.for('nbrowser.docGen');
  const refsSym = Symbol.for('nbrowser.refs');
  if (!window[docGenSym]) {
    window[docGenSym] = 'dg-' + Math.random().toString(36).slice(2) + '-' + Date.now().toString(36);
  }
  if (!window[refsSym]) {
    window[refsSym] = { nextUid: 1, nodeToUid: new WeakMap(), uidToNode: new Map() };
  }
  const refStore = window[refsSym];
  const uidForNode = (node) => {
    let uid = refStore.nodeToUid.get(node);
    if (!uid) {
      uid = refStore.nextUid;
      refStore.nextUid += 1;
      refStore.nodeToUid.set(node, uid);
      refStore.uidToNode.set(uid, node);
    }
    return uid;
  };
  const nativeInteractive = Array.from(document.querySelectorAll('button,input,select,textarea,a[href],[role=button],[role=link],[role=checkbox],[role=radio]'));
  const seenCandidates = new Set(nativeInteractive);
  const candidateList = nativeInteractive.slice();
  const INTERACTIVE_TAGS = { A: 1, BUTTON: 1, INPUT: 1, SELECT: 1, TEXTAREA: 1, DETAILS: 1, SUMMARY: 1 };
  const allDomNodes = document.body ? document.body.querySelectorAll('*') : [];
  const maxCursorScan = Math.min(allDomNodes.length, 2500);
  for (let i = 0; i < maxCursorScan; i += 1) {
    const el = allDomNodes[i];
    if (seenCandidates.has(el) || INTERACTIVE_TAGS[el.tagName]) continue;
    if (el.tagName === 'LABEL') {
      const hiddenCtrl = el.querySelector('input[type="checkbox"], input[type="radio"]');
      if (hiddenCtrl && !visible(hiddenCtrl) && visible(el)) {
        seenCandidates.add(el);
        candidateList.push(el);
        continue;
      }
    }
    const hasOnclick = el.hasAttribute && (el.hasAttribute('onclick') || typeof el.onclick === 'function');
    const tabIdx = el.getAttribute ? el.getAttribute('tabindex') : null;
    const hasTabIndex = tabIdx !== null && Number(tabIdx) >= 0;
    let hasPointer = false;
    if (!hasOnclick && !hasTabIndex) {
      try {
        hasPointer = getComputedStyle(el).cursor === 'pointer';
      } catch (_) {
        hasPointer = false;
      }
    }
    if ((hasOnclick || hasTabIndex || hasPointer) && visible(el)) {
      seenCandidates.add(el);
      candidateList.push(el);
    }
  }
  const candidates = candidateList;
  const candidateTotal = candidates.length;
  const candidateScanEnd = Math.min(candidateTotal, limits.interactive);
  const elements = [];
  let hasPasswordField = false;
  let hasSearchField = false;
  let eligibleIndex = 0;
  for (let index = 0; index < candidateScanEnd; index += 1) {
    const node = candidates[index];
    const tag = node.tagName.toLowerCase();
    const type = (node.getAttribute('type') || '').toLowerCase();
    const hiddenLabelInput = tag === 'label' ? node.querySelector('input[type="checkbox"], input[type="radio"]') : null;
    let kind = 'other';
    if (tag === 'a' || node.getAttribute('href') !== null) kind = 'link';
    else if (tag === 'button' || node.getAttribute('role') === 'button' || (tag === 'input' && ['submit','button'].includes(type))) kind = 'button';
    else if ((tag === 'input' && type === 'checkbox') || (hiddenLabelInput && (hiddenLabelInput.type || '').toLowerCase() === 'checkbox')) kind = 'checkbox';
    else if ((tag === 'input' && type === 'radio') || (hiddenLabelInput && (hiddenLabelInput.type || '').toLowerCase() === 'radio')) kind = 'radio';
    else if (tag === 'input') kind = 'input';
    else if (tag === 'select') kind = 'select';
    else if (tag === 'textarea') kind = 'textarea';
    else if (!INTERACTIVE_TAGS[node.tagName]) kind = 'button';
    const shown = visible(node);
    if (!options.include_hidden && !shown) continue;
    if (shown && tag === 'input') {
      const name = String(node.getAttribute('name') || '').toLowerCase();
      const searchLabel = String(node.getAttribute('aria-label') || node.getAttribute('placeholder') || '').toLowerCase();
      hasPasswordField = hasPasswordField || type === 'password';
      hasSearchField = hasSearchField || type === 'search'
        || ['q', 'query', 'search'].includes(name)
        || node.getAttribute('role') === 'searchbox'
        || searchLabel.includes('search');
    }
    // `data-nbrowser="field:email"` is the page author's own statement
    // of intent, and the Tier 1 proposer decides on it. The field was declared
    // on the wire and bound to `null` here, so no page could ever fill it.
    //
    // Emitted RAW — `<type>:<value>`, the two halves the donor splits into
    // `ElementHint` — and only when it PARSES: a colon at index 0 or none at
    // all yields no type, which is exactly `a11y.rs:332-339` refusing to build
    // one. `clean`, never `diagnostic`: the ' … [truncated]' suffix that one
    // appends would corrupt a hint that still parses.
    const hintAttribute = node.getAttribute ? node.getAttribute('data-nbrowser') : null;
    const hint = hintAttribute && hintAttribute.indexOf(':') > 0 ? clean(hintAttribute) : null;
    const pageIndex = eligibleIndex;
    eligibleIndex += 1;
    if (pageIndex < options.offset || elements.length >= options.limit) continue;
    const form = node.form || (node.closest ? node.closest('form') : null);
    const hasFormAction = Boolean(node.hasAttribute && node.hasAttribute('formaction'));
    const resolvedFormAction = hasFormAction ? safeFormAction(node.getAttribute('formaction') || '') : null;
    const onclickAttr = node.getAttribute ? (node.getAttribute('onclick') || '') : '';
    const isSubmitHandler = /submit\s*\(|\.submit\b/i.test(onclickAttr);
    const hasMutatingHandler = isSubmitHandler || /fetch\s*\(|xmlhttprequest|\.ajax\s*\(|sendbeacon|method\s*:\s*['"](?:post|delete|put|patch)['"]/i.test(onclickAttr);
    const rawHref = (node.getAttribute('href') || '').split('?')[0].split('#')[0];
    const isDownload = Boolean((tag === 'a' && node.hasAttribute('download')) || (tag === 'a' && /\.(?:zip|tar\.gz|tar|gz|pdf|exe|bin|dmg|pkg|iso|csv|xlsx)$/i.test(rawHref)));
    const elementContext = resolvedFormAction ? clean(resolvedFormAction, 512) : (hasMutatingHandler ? (isSubmitHandler ? 'submit' : 'mutating') : (isDownload ? 'download' : null));
    let selectOptions = null;
    if (tag === 'select') {
      selectOptions = [];
      const optionScanEnd = Math.min(node.options.length, 10);
      for (let optionIndex = 0; optionIndex < optionScanEnd; optionIndex += 1) {
        selectOptions.push(diagnostic(node.options[optionIndex].textContent));
      }
    }
    const nUid = uidForNode(node);
    const checkedState = ['checkbox','radio'].includes(kind)
      ? Boolean(hiddenLabelInput ? hiddenLabelInput.checked : node.checked)
      : null;
    elements.push({
      id: index,
      ref: '@e' + nUid,
      node_uid: nUid,
      selector: cssPath(node),
      kind,
      label: diagnostic(node.getAttribute('aria-label') || node.innerText || node.textContent || node.placeholder || node.name || type),
      name: node.name ? diagnostic(node.name) : null,
      value: (tag === 'input' || tag === 'textarea' || tag === 'select') ? '[REDACTED]' : null,
      placeholder: node.placeholder ? diagnostic(node.placeholder) : null,
      href: tag === 'a' ? node.href : null,
      input_type: type ? safeInputType(type) : null,
      autocomplete: node.getAttribute ? (node.getAttribute('autocomplete') || null) : null,
      disabled: Boolean(node.disabled),
      form_index: form ? (formIndexes.has(form) ? formIndexes.get(form) : 0) : null,
      context: elementContext,
      hint: hint,
      checked: checkedState,
      options: selectOptions,
      frame_index: null,
      frame_id: null,
      is_visible: shown
    });
  }
  // Text is collected by walking TEXT NODES, not by selecting elements.
  //
  // The selector this replaces listed h1..h6, p, td, pre and code, and then
  // reached span and anchor text ONLY under a `main` or `article` ancestor. It
  // gated span behind a landmark and never queried div at all. On an ordinary
  // server-rendered page — quotes.toscrape.com, whose every quote is a
  // div.quote > span.text — visible_text came back as
  // "Quotes to Scrape Login Top Ten tags Quotes by: GoodReads.com Made with by
  // Zyte": the chrome, and not one quote or author. No truncation flag, no
  // error.
  //
  // Three constraints decide whether the replacement is safe, and each is the
  // reason a simpler fix is wrong:
  //  - Adding div,span to the selector would NOT work. textContent is
  //    recursive, so every nested wrapper re-emits its descendants' text and
  //    the scan budget is spent on duplicates before any leaf is reached.
  //    Walking text nodes and coalescing to the nearest block ancestor emits
  //    each sentence exactly once.
  //  - Landmarks are NOT skipped. Dropping nav/header/footer/aside would delete
  //    content returned today (this very page keeps "Quotes to Scrape",
  //    "Login", and its byline there) and many sites put the h1 in a header.
  //    Only script/style/noscript/template are suppressed — elements whose text
  //    is never rendered prose.
  //  - Visibility is resolved PER BLOCK, not per text node, and the walk is
  //    hard-bounded. `visible()` calls getComputedStyle and
  //    getBoundingClientRect; running it per text node on a large DOM is an
  //    unbounded forced layout, which would trade a wrong answer for a hang.
  const textNodes = [];
  const visibleCards = new Set();
  const visibleArticles = new Set();
  const SUPPRESSED = { SCRIPT: 1, STYLE: 1, NOSCRIPT: 1, TEMPLATE: 1 };
  const BLOCKISH = {
    P: 1, DIV: 1, LI: 1, TD: 1, TH: 1, PRE: 1, BLOCKQUOTE: 1, SECTION: 1,
    ARTICLE: 1, HEADER: 1, FOOTER: 1, ASIDE: 1, NAV: 1, MAIN: 1, FIGCAPTION: 1,
    DD: 1, DT: 1, H1: 1, H2: 1, H3: 1, H4: 1, H5: 1, H6: 1, BODY: 1,
  };
  const blockOf = (node) => {
    let owner = node.parentElement;
    while (owner && !BLOCKISH[owner.tagName] && owner.parentElement) owner = owner.parentElement;
    return owner;
  };
  // Suppression is a property of the TEXT NODE's ancestry, never of the block
  // it is grouped under. SCRIPT and STYLE are not BLOCKISH, so blockOf climbs
  // straight past them to BODY — and testing SUPPRESSED on that owner asks
  // whether BODY is a script, which it never is. Script source then arrives as
  // page prose, which is the injection channel this whole file exists to close.
  const inSuppressedSubtree = (node) => {
    for (let p = node.parentElement; p; p = p.parentElement) {
      if (SUPPRESSED[p.tagName]) return true;
    }
    return false;
  };
  if (document.body) {
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null);
    const visibleBlock = new WeakMap();
    const chunks = new Map();
    const order = [];
    let scanned = 0;
    // `scanned` counts distinct BLOCKS, so a single div holding a million text
    // nodes advances it once and the walk runs to the end of the document.
    // `visited` bounds the walk itself.
    let visited = 0;
    const NODE_BUDGET = 20000;
    let current;
    while (
      (current = walker.nextNode())
      && scanned < limits.text
      && order.length < 200
      && visited < NODE_BUDGET
    ) {
      visited += 1;
      const raw = current.nodeValue;
      if (!raw || !raw.trim()) continue;
      if (inSuppressedSubtree(current)) continue;
      const owner = blockOf(current);
      if (!owner || SUPPRESSED[owner.tagName]) continue;
      let shown = visibleBlock.get(owner);
      if (shown === undefined) {
        scanned += 1;
        shown = visible(owner);
        visibleBlock.set(owner, shown);
      }
      if (!options.include_hidden && !shown) continue;
      if (!chunks.has(owner)) {
        chunks.set(owner, []);
        order.push(owner);
        if (shown && owner.closest) {
          const article = owner.closest('article');
          const roleItem = owner.closest('[role=listitem]');
          const listItem = owner.closest('li');
          if (article) visibleArticles.add(article);
          const card = article || roleItem
            || (listItem && listItem.closest('main') ? listItem : null);
          if (card) visibleCards.add(card);
        }
      }
      chunks.get(owner).push(raw);
    }
    for (const owner of order) {
      if (owner.tagName === 'PRE' || (owner.closest && owner.closest('pre'))) {
        const pre = owner.tagName === 'PRE' ? owner : owner.closest('pre');
        const codeText = String(pre.textContent || '').trim();
        if (codeText) {
          const formatted = '```\n' + (codeText.length > 2000 ? codeText.slice(0, 2000) + ' … [truncated]' : codeText) + '\n```';
          textNodes.push(formatted);
        }
        continue;
      }
      if (/^H[1-6]$/.test(owner.tagName)) {
        const level = parseInt(owner.tagName.slice(1), 10);
        const prefix = '#'.repeat(level) + ' ';
        const content = diagnostic(chunks.get(owner).join(' '), 500);
        if (content) textNodes.push(prefix + content);
        continue;
      }
      if (owner.tagName === 'LI') {
        const content = diagnostic(chunks.get(owner).join(' '), 500);
        if (content) textNodes.push('- ' + content);
        continue;
      }
      if (owner.tagName === 'TR') {
        const cellNodes = owner.querySelectorAll('th, td');
        const cells = [];
        for (let ci = 0; ci < cellNodes.length; ci += 1) {
          const ctext = diagnostic(cellNodes[ci].textContent, 200);
          if (ctext) cells.push(ctext);
        }
        if (cells.length > 0) {
          textNodes.push('| ' + cells.join(' | ') + ' |');
        }
        continue;
      }
      const text = diagnostic(chunks.get(owner).join(' '), 500);
      if (text) textNodes.push(text);
    }
  }
  let cards = null;
  let cardsTruncated = null;
  if (options.include_cards) {
    const rawCards = document.querySelectorAll('article, [role=listitem], main li');
    const cardScanEnd = Math.min(rawCards.length, limits.card);
    cardsTruncated = rawCards.length > cardScanEnd ? true : null;
    cards = [];
    for (let index = 0; index < cardScanEnd; index += 1) {
      const node = rawCards[index];
      if (!visible(node)) continue;
      if (cards.length >= 50) {
        cardsTruncated = true;
        break;
      }
      const titleNode = node.querySelector('h1,h2,h3,h4,h5,h6,a') || node;
      cards.push({
        id: `c${index}`,
        title: diagnostic(titleNode.textContent),
        metadata: [],
        child_element_ids: []
      });
    }
  }
  // State is OBSERVED, never asserted. This used to be the literal 'ready', so
  // a CAPTCHA, a WAF interstitial and an empty shell all reported a healthy
  // page and the consumer concluded the site was simply blank. `blocked` and
  // `empty` are the honest answers; each carries the marker that produced it so
  // the caller can act instead of guess.
  const bodyText = clean(document.body ? (document.body.innerText || '') : '', 4000);
  const lowerText = bodyText.toLowerCase();
  const lowerTitle = String(document.title || '').toLowerCase();

  // Vendor challenge widgets, matched by DOM presence rather than by prose, so
  // an article ABOUT bot detection is not mistaken for one.
  const challengeSelectors = [
    ['#challenge-running', 'cloudflare challenge'],
    ['#cf-challenge-running', 'cloudflare challenge'],
    ['[class*="cf-browser-verification"]', 'cloudflare browser verification'],
    ['iframe[src*="recaptcha"]', 'recaptcha'],
    ['iframe[src*="hcaptcha"]', 'hcaptcha'],
    ['iframe[src*="turnstile"]', 'cloudflare turnstile'],
    ['iframe[title*="challenge" i]', 'challenge iframe'],
    ['#px-captcha', 'perimeterx captcha'],
    ['[id*="datadome" i]', 'datadome'],
  ];
  let blockedReason = null;
  for (const [selector, label] of challengeSelectors) {
    let hit = null;
    try { hit = document.querySelector(selector); } catch (_) { hit = null; }
    if (hit) { blockedReason = label; break; }
  }

  // Interstitial wording, only trusted on a page that carries almost no other
  // content — a long article mentioning these phrases is not a wall.
  if (!blockedReason && bodyText.length < 1200) {
    const phrases = [
      ['are you a robot', 'bot challenge'],
      ['verify you are human', 'human verification'],
      ['checking your browser', 'browser check interstitial'],
      ['just a moment', 'challenge interstitial'],
      ['enable javascript and cookies', 'javascript/cookie gate'],
      ['access denied', 'access denied'],
      ['unusual activity', 'unusual-activity block'],
      ['request blocked', 'request blocked'],
      ['rate limit', 'rate limited'],
    ];
    for (const [needle, label] of phrases) {
      if (lowerText.includes(needle) || lowerTitle.includes(needle)) { blockedReason = label; break; }
    }
  }

  // `PageState::Blocked` is a serde newtype variant, so it must be emitted as
  // {blocked: reason}; the unit variants are bare strings.
  // The HTTP status the document was served with. Without it a 404, a 403
  // bot-block, a 451 and a real article are the same answer: MDN's own missing
  // page returns a full navigation shell, `state: ready`, and the word "not
  // found" buried in prose — so the caller has to guess a status from wording.
  // Navigation timing carries it with no CDP plumbing and no extra round trip.
  let httpStatus = null;
  try {
    const nav = performance.getEntriesByType('navigation')[0];
    if (nav && typeof nav.responseStatus === 'number' && nav.responseStatus > 0) {
      httpStatus = nav.responseStatus;
    }
  } catch (e) { /* the view is still valid without it */ }

  // Framework-shell markers. A page mid-hydration legitimately has no controls
  // yet, so without these the check below calls every Next.js or React page
  // cloaked — which is exactly the false positive the detector had to be
  // repaired for. Any one marker is enough to withhold the verdict.
  let shellRoot = false;
  let shellData = false;
  let scriptCount = 0;
  try {
    shellData = typeof window.__NEXT_DATA__ !== 'undefined';
    shellRoot = !!(document.getElementById('__next') || document.getElementById('root')
      || document.getElementById('react-root') || document.getElementById('app'));
    scriptCount = document.querySelectorAll('script').length;
  } catch (e) { /* the view is still valid without it */ }
  const looksLikeShell = shellData || shellRoot
    || (document.readyState !== 'complete' && scriptCount > 0);

  const nothingCameBack = !bodyText && elements.length === 0 && textNodes.length === 0;
  // Measured off the LIVE page, never off `textNodes`: the evidence this view
  // returns is capped, and a verdict read from a capped value saturates at the
  // cap and can never cross a threshold set at it. `innerText` is also the
  // right question — it is what layout actually shows, so text hidden from the
  // human does not count toward calling the page substantial.
  let readableLength = 0;
  try {
    readableLength = String((document.body && document.body.innerText) || '')
      .replace(/\s+/g, ' ').trim().length;
  } catch (e) { /* the view is still valid without it */ }
  let state = 'ready';
  // A 4xx or 5xx is NOT ready, however complete the shell around it looks. The
  // reason names the status so the caller acts instead of parsing prose.
  if (httpStatus !== null && httpStatus >= 400) {
    blockedReason = blockedReason || `server responded ${httpStatus}`;
    state = { blocked: blockedReason };
  } else if (blockedReason) {
    state = { blocked: blockedReason };
  } else if (nothingCameBack) {
    state = 'empty';
    blockedReason = document.readyState !== 'complete'
      ? `document is ${document.readyState} and carries no text or elements`
      : (looksLikeShell
        ? 'document completed as a framework shell with nothing rendered into it yet (client-rendered)'
        : 'document completed with no visible text and no elements (client-rendered, gated, or refused upstream)');
  } else if (document.readyState !== 'complete') {
    state = 'loading';
  }
  // The cloaking verdict is NOT decided here. This probe reports what it
  // observed — the counts and the markers below — and `crate::cloaking` reaches
  // the conclusion in Rust, where it can be tested without a browser.
  const hasArticle = visibleArticles.size === 1;
  const hasSearchContext = /(?:^|[?&])(?:q|query|search)=/i.test(location.search)
    || lowerTitle.includes('search result');
  const pageHint = hasPasswordField ? 'login page'
    : (hasSearchField && hasSearchContext && visibleCards.size > 1 ? 'search results'
      : (hasArticle ? 'article page'
        : (visibleFormCount ? 'form page'
          : (visibleCards.size ? 'collection page' : 'content page'))));

  let webmcpSummary = null;
  try {
    const rawTools = [];
    const mc = (navigator && navigator.modelContext && Array.isArray(navigator.modelContext.tools))
      ? navigator.modelContext.tools
      : (window.__webmcp && Array.isArray(window.__webmcp.tools) ? window.__webmcp.tools : []);
    for (const t of mc) {
      if (t && typeof t.name === 'string') rawTools.push(t);
    }
    const mcpScripts = document.querySelectorAll('script[type="application/mcp+json"]');
    for (let si = 0; si < mcpScripts.length; si += 1) {
      try {
        const parsed = JSON.parse(mcpScripts[si].textContent || '{}');
        const list = Array.isArray(parsed) ? parsed : (Array.isArray(parsed.tools) ? parsed.tools : []);
        for (const t of list) {
          if (t && typeof t.name === 'string') rawTools.push(t);
        }
      } catch (_) {}
    }
    if (rawTools.length > 0) {
      const _enc = new TextEncoder();
      const utf8Len = (s) => _enc.encode(String(s || '')).length;
      const utf8Slice = (s, maxBytes) => {
        const str = String(s || '').replace(/\s+/g, ' ').trim();
        if (utf8Len(str) <= maxBytes) return str;
        let out = '';
        let used = 0;
        for (const ch of str) {
          const b = utf8Len(ch);
          if (used + b > maxBytes) break;
          out += ch;
          used += b;
        }
        return out;
      };
      const catalog = [];
      let bytes = 256;
      let truncated = false;
      for (let ti = 0; ti < rawTools.length; ti += 1) {
        if (catalog.length >= 16) { truncated = true; break; }
        const rt = rawTools[ti];
        const desc = String(rt.description || '').replace(/\s+/g, ' ').trim();
        if (utf8Len(desc) > 160) truncated = true;
        const entry = {
          name: utf8Slice(rt.name, 120),
          description: utf8Slice(desc, 160),
          origin: safeOrigin(location.href),
          frameId: 'main'
        };
        const entryLen = utf8Len(JSON.stringify(entry)) + 1;
        if (bytes + entryLen > 4096) { truncated = true; continue; }
        bytes += entryLen;
        catalog.push(entry);
      }
      webmcpSummary = {
        experimental: true,
        untrusted: true,
        status: 'ready',
        available: catalog.length > 0,
        toolCount: rawTools.length,
        tools: catalog,
        truncated
      };
    }
  } catch (_) { webmcpSummary = null; }

  return {
    url: location.href,
    title: diagnostic(document.title),
    page_hint: pageHint,
    doc_gen: String(window[docGenSym] || ''),
    elements,
    forms,
    visible_text: clean(textNodes.join(' '), 40000),
    text_blocks: textNodes,
    state,
    http_status: httpStatus,
    element_cap: candidateTotal > elements.length ? `${elements.length}/${candidateTotal}` : null,
    blocked_reason: blockedReason ? diagnostic(blockedReason) : null,
    shell_markers: {
      ready_complete: document.readyState === 'complete',
      has_next_data: shellData,
      has_framework_root: shellRoot,
      script_tag_count: scriptCount
    },
    interactive_total: candidateTotal,
    readable_length: readableLength,
    session_context: null,
    cards,
    cards_truncated: cardsTruncated,
    webmcp: webmcpSummary
  };
}"""
