/* AiCSO UI 增强脚本 — 渐进增强（SSR表单无JS也可用） */
(function () {
  "use strict";

  /* ---------- Toast ---------- */
  window.toast = function (message, type) {
    let root = document.getElementById("toast-root");
    if (!root) {
      root = document.createElement("div");
      root.id = "toast-root";
      document.body.appendChild(root);
    }
    const el = document.createElement("div");
    el.className = "toast " + (type || "");
    el.textContent = message;
    root.appendChild(el);
    setTimeout(() => {
      el.style.opacity = "0";
      el.style.transition = "opacity .3s";
      setTimeout(() => el.remove(), 320);
    }, 3200);
  };

  /* ---------- fetchJSON ---------- */
  window.fetchJSON = async function (url, options) {
    try {
      const resp = await fetch(url, options);
      if (!resp.ok) throw new Error("HTTP " + resp.status);
      return await resp.json();
    } catch (e) {
      toast("请求失败: " + e.message, "error");
      throw e;
    }
  };

  /* ---------- 相对时间 ---------- */
  function relativeTime(iso) {
    // 服务端时间戳是naive-UTC（datetime.utcnow().isoformat()），必须按UTC
    // 解析——按浏览器本地时区解析会让东八区用户看到"8小时前"（#56发现35）
    let then = new Date(iso).getTime();
    if (isNaN(then)) return iso;
    if (!/[Zz]|[+-]\d{2}:?\d{2}$/.test(iso)) {
      then = new Date(iso + "Z").getTime();
    }
    if (isNaN(then)) return iso;
    const diff = Date.now() - then;
    if (diff < 0) return "刚刚";
    const s = diff / 1000;
    if (s < 60) return Math.floor(s) + "秒前";
    if (s < 3600) return Math.floor(s / 60) + "分钟前";
    if (s < 86400) return Math.floor(s / 3600) + "小时前";
    return Math.floor(s / 86400) + "天前";
  }
  function renderRelativeTimes() {
    document.querySelectorAll("[data-reltime]").forEach((el) => {
      const orig = el.getAttribute("data-reltime");
      el.textContent = relativeTime(orig);
      el.title = orig;
    });
  }
  renderRelativeTimes();
  setInterval(renderRelativeTimes, 30000);

  /* ---------- 表单提交 loading ---------- */
  document.addEventListener("submit", (e) => {
    const btn = e.target.querySelector('button[type="submit"], .btn.primary');
    if (btn && !btn.classList.contains("no-loading")) {
      btn.classList.add("loading");
      const original = btn.innerHTML;
      btn.innerHTML = "处理中…";
      // SSR表单整页跳转；若3秒未跳转则恢复并提示（异常兜底）
      setTimeout(() => {
        btn.classList.remove("loading");
        btn.innerHTML = original;
      }, 3000);
    }
  });

  /* ---------- 系统状态chips（/api/metrics 自动刷新） ---------- */
  const chipRoot = document.getElementById("sys-chips");
  if (chipRoot) {
    const render = (m) => {
      const degraded = !!m.degraded;
      const overload = !!m.overload;
      // backlog_age_ms 在 status().metrics 嵌套层（读顶层恒undefined显示0，#56发现34）
      const backlog = m.metrics ? m.metrics.backlog_age_ms : m.backlog_age_ms;
      const state = degraded ? "降级模式" : (overload ? "过载模式" : "System One 正常");
      const cls = degraded || overload ? " warn" : "";
      chipRoot.innerHTML =
        '<span class="chip' + cls + '"><span class="dot"></span>' + state + "</span>" +
        '<span class="chip">队列 ' + m.queue_depth + "/" + m.queue_max + "</span>" +
        '<span class="chip">积压 ' + (backlog == null ? "0" : backlog) + "ms</span>";
    };
    const refresh = async () => {
      try {
        const m = await fetchJSON("/api/metrics");
        render(m);
      } catch (e) {
        chipRoot.innerHTML =
          '<span class="chip warn"><span class="dot"></span>指标不可用</span>';
      }
    };
    refresh();
    setInterval(refresh, 10000);
  }

  /* ---------- 确认弹窗（data-confirm） ---------- */
  document.addEventListener("submit", (e) => {
    const form = e.target;
    const msg = form.getAttribute("data-confirm");
    if (msg && !window.confirm(msg)) e.preventDefault();
  });
})();
