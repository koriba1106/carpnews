'use strict';

(() => {
  const MAX_ITEMS_LIMIT = 500;
  const FETCH_TIMEOUT_MS = 8000;
  const RECENT_THRESHOLD_MS = 24 * 60 * 60 * 1000;
  const ALLOWED_FILTER_TYPES = Object.freeze(new Set(['all', 'player', 'category', 'team']));

  /**
   * 検索・比較用に文字列をNFKC正規化＆小文字化する
   */
  function normalizeQuery(str) {
    if (typeof str !== 'string') return '';
    return str.normalize('NFKC').trim().toLowerCase();
  }

  /**
   * 絶対URLかつ http/https スキームであることを厳格に検証する
   */
  function sanitizeHttpUrl(urlStr) {
    if (typeof urlStr !== 'string') return null;
    const trimmed = urlStr.trim();
    // 相対パスがベースURLで解決されるのを防ぐため、先頭スキームを正規表現で必須化
    if (!/^https?:\/\//i.test(trimmed) || trimmed.length > 2048) {
      return null;
    }
    try {
      const parsed = new URL(trimmed);
      if ((parsed.protocol === 'http:' || parsed.protocol === 'https:') && parsed.hostname) {
        return parsed.href;
      }
    } catch (_) {
      // Invalid URL
    }
    return null;
  }

  class AppState {
    constructor() {
      this.dataset = [];
      this.activeFilter = { type: 'all', value: 'ALL' };
      this.searchQuery = '';
    }

    setDataset(rawItems) {
      if (!Array.isArray(rawItems)) {
        this.dataset = [];
        return;
      }

      const validItems = [];
      const sliceLimit = Math.min(rawItems.length, MAX_ITEMS_LIMIT);

      for (let i = 0; i < sliceLimit; i++) {
        const item = rawItems[i];
        if (!item || typeof item !== 'object') continue;

        const safeLink = sanitizeHttpUrl(item.link);
        if (!safeLink) continue;

        const title = typeof item.title === 'string' && item.title.trim() !== ''
          ? item.title.trim().slice(0, 300)
          : '無題のニュース';

        const parsedTime = typeof item.pubDate === 'string' ? Date.parse(item.pubDate) : NaN;
        const pubDate = !Number.isNaN(parsedTime) ? new Date(parsedTime).toISOString() : new Date(0).toISOString();

        const source = typeof item.source === 'string' && item.source.trim() !== ''
          ? item.source.trim().slice(0, 100)
          : 'News';

        const teamLevel = typeof item.teamLevel === 'string' && item.teamLevel.trim() !== ''
          ? item.teamLevel.trim().slice(0, 40)
          : null;

        const players = Array.isArray(item.players)
          ? item.players.filter(p => typeof p === 'string' && p.trim() !== '').map(p => p.trim().slice(0, 40)).slice(0, 15)
          : [];

        const categories = Array.isArray(item.categories)
          ? item.categories.filter(c => typeof c === 'string' && c.trim() !== '').map(c => c.trim().slice(0, 40)).slice(0, 10)
          : [];

        // 検索高速化のため正規化済みコーパスを事前生成
        const searchCorpus = normalizeQuery([
          title,
          teamLevel,
          source,
          ...players,
          ...categories
        ].filter(Boolean).join(' '));

        validItems.push(Object.freeze({
          id: typeof item.id === 'string' ? item.id.slice(0, 32) : String(i),
          title,
          link: safeLink,
          pubDate,
          pubTimeMs: !Number.isNaN(parsedTime) ? parsedTime : 0,
          source,
          teamLevel,
          players: Object.freeze(players),
          categories: Object.freeze(categories),
          searchCorpus
        }));
      }

      this.dataset = validItems;
    }

    setFilter(type, value) {
      if (!ALLOWED_FILTER_TYPES.has(type) || typeof value !== 'string') {
        this.activeFilter = { type: 'all', value: 'ALL' };
        return;
      }
      this.activeFilter = { type, value };
    }

    getFiltered() {
      const q = normalizeQuery(this.searchQuery);
      const { type, value } = this.activeFilter;

      return this.dataset.filter(item => {
        if (type === 'player' && !item.players.includes(value)) return false;
        if (type === 'category' && !item.categories.includes(value)) return false;
        if (type === 'team' && item.teamLevel !== value) return false;

        if (q && !item.searchCorpus.includes(q)) {
          return false;
        }
        return true;
      });
    }
  }

  const state = new AppState();
  let toastTimer = null;

  function isRecent(pubTimeMs) {
    if (!pubTimeMs || pubTimeMs <= 0) return false;
    const diff = Date.now() - pubTimeMs;
    return diff >= -300000 && diff < RECENT_THRESHOLD_MS;
  }

  function formatTimestamp(pubTimeMs) {
    if (!pubTimeMs || pubTimeMs <= 0) return '--/-- --:--';
    const d = new Date(pubTimeMs);
    if (Number.isNaN(d.getTime())) return '--/-- --:--';
    return `${d.getMonth() + 1}/${d.getDate()} ${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
  }

  function notify(message) {
    const toast = document.getElementById('toast');
    if (!toast) return;
    toast.textContent = String(message);
    toast.classList.add('show');
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove('show'), 2200);
  }

  async function copyToClipboard(text) {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        notify('記事URLをコピーしました');
        return;
      }
      const textarea = document.createElement('textarea');
      textarea.value = text;
      textarea.setAttribute('readonly', '');
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
      notify('記事URLをコピーしました');
    } catch (_) {
      notify('URLのコピーに失敗しました');
    }
  }

  function updateStats() {
    const totalEl = document.getElementById('stat-total');
    const gameEl = document.getElementById('stat-game');
    const rosterEl = document.getElementById('stat-roster');
    const recentEl = document.getElementById('stat-recent');

    if (totalEl) totalEl.textContent = String(state.dataset.length);
    if (gameEl) {
      gameEl.textContent = String(
        state.dataset.filter(i => i.categories.includes('試合・戦評')).length
      );
    }
    if (rosterEl) {
      rosterEl.textContent = String(
        state.dataset.filter(i =>
          i.categories.includes('公示・登録抹消') ||
          i.categories.includes('ドラフト・新戦力') ||
          i.categories.includes('契約・編成')
        ).length
      );
    }
    if (recentEl) {
      recentEl.textContent = String(
        state.dataset.filter(i => isRecent(i.pubTimeMs)).length
      );
    }
  }

  function createBadge(text, className) {
    const span = document.createElement('span');
    span.className = `badge ${className}`;
    span.textContent = text;
    return span;
  }

  function renderFeed() {
    const container = document.getElementById('feed-container');
    if (!container) return;

    const filtered = state.getFiltered();
    container.setAttribute('aria-busy', 'false');
    container.replaceChildren();

    if (filtered.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'empty-placeholder';
      empty.textContent = '該当するニュースは見つかりませんでした。';
      container.appendChild(empty);
      return;
    }

    const fragment = document.createDocumentFragment();

    filtered.forEach(item => {
      const article = document.createElement('article');

      const cardLink = document.createElement('a');
      cardLink.href = item.link;
      cardLink.target = '_blank';
      cardLink.rel = 'noopener noreferrer';
      cardLink.className = 'feed-card';

      // 1行目: タグ
      const rowTags = document.createElement('div');
      rowTags.className = 'card-row-tags';

      if (isRecent(item.pubTimeMs)) {
        rowTags.appendChild(createBadge('NEW', 'badge-new'));
      }
      if (item.teamLevel) {
        rowTags.appendChild(createBadge(item.teamLevel, 'badge-team'));
      }
      item.players.forEach(player => {
        rowTags.appendChild(createBadge(`⚾ ${player}`, 'badge-player'));
      });
      item.categories.forEach(cat => {
        rowTags.appendChild(createBadge(cat, 'badge-category'));
      });

      // 2行目: タイトルとURL
      const rowTitleUrl = document.createElement('div');
      rowTitleUrl.className = 'card-row-title-url';

      const headline = document.createElement('h2');
      headline.className = 'card-headline';
      headline.textContent = item.title;

      const urlText = document.createElement('span');
      urlText.className = 'card-url-text';
      urlText.textContent = item.link;

      rowTitleUrl.appendChild(headline);
      rowTitleUrl.appendChild(urlText);

      // 3行目: 日時・メディア元・共有ボタン
      const rowInfo = document.createElement('div');
      rowInfo.className = 'card-row-info';

      const metaLeft = document.createElement('div');
      metaLeft.className = 'card-meta-left';

      const timeEl = document.createElement('time');
      timeEl.className = 'card-timestamp';
      timeEl.setAttribute('datetime', item.pubDate);
      timeEl.textContent = formatTimestamp(item.pubTimeMs);

      const sourceEl = document.createElement('span');
      sourceEl.className = 'card-source';
      sourceEl.textContent = item.source;

      metaLeft.appendChild(timeEl);
      metaLeft.appendChild(sourceEl);

      const shareBtn = document.createElement('button');
      shareBtn.type = 'button';
      shareBtn.className = 'btn-share';
      shareBtn.dataset.shareUrl = item.link;
      shareBtn.textContent = 'URL共有';

      rowInfo.appendChild(metaLeft);
      rowInfo.appendChild(shareBtn);

      cardLink.appendChild(rowTags);
      cardLink.appendChild(rowTitleUrl);
      cardLink.appendChild(rowInfo);
      article.appendChild(cardLink);
      fragment.appendChild(article);
    });

    container.appendChild(fragment);
  }

  function setupControls() {
    // Prototype Pollution を完全に防ぐため Map を使用
    const playerCounts = new Map();
    const categoryCounts = new Map();
    const teamCounts = new Map();

    state.dataset.forEach(item => {
      if (item.teamLevel) {
        teamCounts.set(item.teamLevel, (teamCounts.get(item.teamLevel) || 0) + 1);
      }
      item.players.forEach(p => {
        playerCounts.set(p, (playerCounts.get(p) || 0) + 1);
      });
      item.categories.forEach(c => {
        categoryCounts.set(c, (categoryCounts.get(c) || 0) + 1);
      });
    });

    const buildButtons = (containerId, countMap, type) => {
      const container = document.getElementById(containerId);
      if (!container) return;
      container.replaceChildren();
      const fragment = document.createDocumentFragment();

      Array.from(countMap.entries())
        .sort((a, b) => b[1] - a[1])
        .forEach(([val, count]) => {
          const btn = document.createElement('button');
          btn.type = 'button';
          btn.className = 'chip';
          btn.dataset.type = type;
          btn.dataset.value = val;
          btn.textContent = `${val} (${count})`;
          fragment.appendChild(btn);
        });

      container.appendChild(fragment);
    };

    buildButtons('filter-player', playerCounts, 'player');
    buildButtons('filter-category', categoryCounts, 'category');
    buildButtons('filter-team', teamCounts, 'team');

    const controlDeck = document.querySelector('.control-deck');
    if (controlDeck) {
      controlDeck.addEventListener('click', (e) => {
        const target = e.target.closest('.chip');
        if (!target) return;

        document.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
        target.classList.add('active');

        state.setFilter(target.dataset.type || 'all', target.dataset.value || 'ALL');
        renderFeed();
      });
    }

    const feedContainer = document.getElementById('feed-container');
    if (feedContainer) {
      feedContainer.addEventListener('click', (e) => {
        const shareBtn = e.target.closest('.btn-share');
        if (!shareBtn) return;
        e.preventDefault();
        e.stopPropagation();
        const url = sanitizeHttpUrl(shareBtn.dataset.shareUrl);
        if (url) copyToClipboard(url);
      });
    }

    const searchInput = document.getElementById('search-input');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        state.searchQuery = e.target.value;
        renderFeed();
      });

      window.addEventListener('keydown', (e) => {
        if (e.key === '/' && document.activeElement !== searchInput) {
          e.preventDefault();
          searchInput.focus();
        }
      });
    }
  }

  async function initialize() {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

    try {
      const response = await fetch(`./data/news.json?t=${Date.now()}`, {
        signal: controller.signal,
        headers: { 'Accept': 'application/json' },
        cache: 'no-store',
         credentials: 'same-origin'
      });
      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const data = await response.json();
      state.setDataset(data);

      const syncTimeEl = document.getElementById('sync-time');
      if (syncTimeEl) {
        syncTimeEl.textContent = `LIVE: ${formatTimestamp(Date.now())}`;
      }

      updateStats();
      setupControls();
      renderFeed();
    } catch (err) {
      clearTimeout(timeoutId);
      const syncDot = document.getElementById('sync-dot');
      if (syncDot) syncDot.classList.add('error');

      const syncTimeEl = document.getElementById('sync-time');
      if (syncTimeEl) syncTimeEl.textContent = '同期エラー';

      const container = document.getElementById('feed-container');
      if (container) {
        container.setAttribute('aria-busy', 'false');
        container.replaceChildren();
        const errDiv = document.createElement('div');
        errDiv.className = 'empty-placeholder';
        errDiv.textContent = 'ニュースデータの取得に失敗しました。しばらく待ってから再読み込みしてください。';
        container.appendChild(errDiv);
      }
      console.error('[CarpNewsFeed Error]', err);
    }
  }

  document.addEventListener('DOMContentLoaded', initialize);
})();
