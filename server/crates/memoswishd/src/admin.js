
    function authHeaders() {
      const h = { "Content-Type": "application/json" };
      const t = document.getElementById("token-input").value.trim();
      if (t) h["Authorization"] = "Bearer " + t;
      return h;
    }

    async function api(path, opts = {}) {
      const res = await fetch(path, { ...opts, headers: { ...authHeaders(), ...(opts.headers || {}) } });
      if (!res.ok) throw new Error(res.status + " " + (await res.text()));
      return res.json();
    }

    function label(tag, text, className = "") {
      const el = document.createElement(tag);
      el.textContent = text;
      el.className = className;
      return el;
    }

    function action(text, handler) {
      const button = label("button", text, "secondary");
      button.addEventListener("click", handler);
      return button;
    }

    async function importApkg() {
      const file = document.getElementById("apkg-file").files[0];
      const output = document.getElementById("apkg-status");
      const button = document.getElementById("apkg-upload");
      if (!file || file.size > 10 * 1024 * 1024) {
        output.textContent = "请选择不超过 10 MiB 的 .apkg 文件。";
        return;
      }
      const options = new URLSearchParams();
      const title = document.getElementById("apkg-title").value.trim();
      const language = document.getElementById("apkg-language").value.trim();
      if (title) options.set("title", title);
      if (language) options.set("language", language);
      button.disabled = true;
      output.textContent = "正在上传并导入，请稍候…";
      try {
        const report = await api("/v1/decks/import/apkg?" + options, {
          method: "POST", body: file, headers: { "Content-Type": "application/octet-stream" }
        });
        output.textContent = `已导入「${report.deck.title}」\n笔记 ${report.notes_read}，卡片 ${report.cards_imported}，图片 ${report.media_imported}，省略音频 ${report.audio_omitted}\n`
          + report.warnings.join("\n") + (report.warnings_truncated ? "\n其余警告已省略。" : "");
        await refreshAll();
      } catch (e) {
        output.textContent = "导入失败：" + e.message;
      } finally {
        button.disabled = false;
      }
    }

    async function refreshAll() {
      try {
        const info = await api("/v1/server-info");
        document.getElementById("server-badge").textContent =
          `${info.name} v${info.version} · ${info.mode} · TTS: ${info.tts_engines.join(",")}`;
        const stats = await api("/v1/stats");
        document.getElementById("st-total").textContent = stats.total_cards;
        document.getElementById("st-seen").textContent = stats.seen_cards;
        document.getElementById("st-due").textContent = stats.due_cards;
        document.getElementById("st-starred").textContent = stats.starred_cards;
        document.getElementById("st-ret").textContent = (stats.average_retrievability * 100).toFixed(1) + "%";
        document.getElementById("st-exp").textContent = stats.total_exposures;

        const decks = await api("/v1/decks");
        const list = document.getElementById("decks-list");
        list.replaceChildren();
        decks.forEach(d => {
          const el = document.createElement("div");
          el.className = "item";
          const details = document.createElement("div");
          details.append(label("strong", d.title), label("span", d.language, "pill"),
            label("span", `${d.card_count} cards`, "pill"));
          const actions = document.createElement("div");
          actions.append(action("查看卡片", () => loadDeckCards(d.id, d.title)),
            action("导出", () => exportDeck(d.id)));
          el.append(details, actions);
          list.appendChild(el);
        });
        if (decks.length > 0) loadDeckCards(decks[0].id, decks[0].title);
      } catch (e) {
        document.getElementById("server-badge").textContent = "Error: " + e.message;
      }
    }

    function renderCards(cards, heading) {
      document.getElementById("cards-heading").textContent = heading + ` (${cards.length})`;
      const list = document.getElementById("cards-list");
      list.replaceChildren();
      cards.forEach(c => {
        const el = document.createElement("div");
        el.className = "item";
        const details = document.createElement("div");
        details.append(label("strong", c.front.title), label("span", c.template, "pill"),
          label("div", c.back.title || ""));
        el.append(details, action("AI 解析", () => selectCardExplain(c.id)));
        list.appendChild(el);
      });
    }

    async function loadDeckCards(deckId, title) {
      const cards = await api(`/v1/decks/${deckId}/cards`);
      renderCards(cards, `卡组：${title}`);
    }

    async function loadStarred() {
      const cards = await api("/v1/starred");
      renderCards(cards, "重点记忆库 (Starred)");
    }

    function selectCardExplain(cardId) {
      document.getElementById("explain-card-id").value = cardId;
      runExplain();
    }

    async function runExplain() {
      const cardId = document.getElementById("explain-card-id").value.trim();
      if (!cardId) return;
      const question = document.getElementById("explain-question").value.trim() || null;
      const out = document.getElementById("explain-output");
      out.textContent = "正在生成深度解析...";
      try {
        const exp = await api(`/v1/cards/${cardId}/explain`, {
          method: "POST",
          body: JSON.stringify({ question })
        });
        out.textContent = JSON.stringify(exp, null, 2);
      } catch (e) {
        out.textContent = "解析失败: " + e.message;
      }
    }

    async function exportDeck(deckId) {
      const pack = await api(`/v1/decks/${deckId}/export`);
      document.getElementById("pack-json").value = JSON.stringify(pack, null, 2);
      document.getElementById("pack-status").textContent = `已导出卡组「${pack.deck.title}」（共 ${pack.cards.length} 张卡片）。`;
    }

    async function importPack() {
      const raw = document.getElementById("pack-json").value.trim();
      if (!raw) return;
      try {
        const deck = await api("/v1/decks/import", { method: "POST", body: raw });
        document.getElementById("pack-status").textContent = `导入成功：新卡组 ID=${deck.id}，共 ${deck.card_count} 张卡片。`;
        refreshAll();
      } catch (e) {
        document.getElementById("pack-status").textContent = "导入失败: " + e.message;
      }
    }

    refreshAll();

    document.getElementById("refresh-button").addEventListener("click", refreshAll);

    document.getElementById("starred-button").addEventListener("click", loadStarred);

    document.getElementById("explain-button").addEventListener("click", runExplain);

    document.getElementById("import-button").addEventListener("click", importPack);

    document.getElementById("apkg-upload").addEventListener("click", importApkg);
    for (const event of ["pagehide", "pageshow"]) {
      window.addEventListener(event, () => { document.getElementById("token-input").value = ""; });
    }
