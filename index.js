const express = require('express');
const fs = require('fs');
const path = require('path');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const { marked } = require('marked');
const hljs = require('highlight.js');
const rateLimit = require('express-rate-limit');
const csrf = require('csurf');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const { Pool } = require('pg');

const app = express();

app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrcElem: [
        "'self'",
        "'unsafe-inline'",
        "blob:",
        "https://cdnjs.cloudflare.com",
        "https://cdn.jsdelivr.net"
      ],
      scriptSrc: [
        "'self'",
        "'unsafe-inline'",
        "blob:",
        "https://cdnjs.cloudflare.com",
        "https://cdn.jsdelivr.net"
      ],
      workerSrc: [
        "'self'",
        "blob:"
      ],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net"],
      imgSrc: ["'self'", "data:", "https://cdnjs.cloudflare.com", "http://localhost:3000"],
      connectSrc: ["'self'", "https://cdn.jsdelivr.net"],
      fontSrc: ["'self'", "https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: [],
      // scriptSrcAttr: ["'none'"], // Commented out to allow event handlers
      scriptSrcAttr: ["'unsafe-inline'"],
    },
  },
}));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());

app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { 
    secure: true, // <-- set to true in production
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);

const csrfProtection = csrf({ 
  cookie: {
    httpOnly: true,
    secure: true // <-- set to true in production
  }
});

app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    res.status(403).send('CSRF token validation failed');
  } else {
    console.error(err.stack);
    res.status(500).send('Something broke!');
  }
});

marked.setOptions({
  highlight: function(code, lang) {
    if (lang && hljs.getLanguage(lang)) {
      try {
        return hljs.highlight(code, { language: lang }).value;
      } catch (err) {
        console.error(err);
      }
    }
    return hljs.highlightAuto(code).value;
  },
  langPrefix: 'hljs language-',
  headerIds: false,
  mangle: false
});

const snippetsDir = path.join(__dirname, 'snippets');
if (!fs.existsSync(snippetsDir)) {
  fs.mkdirSync(snippetsDir);
}

const getAllSnippets = async () => {
  const { rows } = await pool.query('SELECT * FROM snippets ORDER BY timestamp DESC');
  return rows;
};

const getNavigation = (currentPage) => `
  <nav style="
    background: #232323;
    padding: 1em 2em;
    margin-bottom: 2em;
    border-bottom: 1px solid #333;
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-radius: 8px 8px 0 0;
    box-shadow: 0 2px 12px #0006;
  ">
    <div style="display: flex; gap: 1.5em;">
      <a href="/" style="color: ${currentPage === 'home' ? '#fff' : '#7ecfff'}; text-decoration: none; font-weight: bold;">Home</a>
      <a href="/admin" style="color: ${currentPage === 'admin' ? '#fff' : '#7ecfff'}; text-decoration: none; font-weight: bold;">Admin</a>
    </div>
    <button id="quick-snippet-btn" style="
      background: #007acc;
      color: white;
      border: none;
      padding: 0.5em 1.2em;
      border-radius: 4px;
      cursor: pointer;
      font-size: 1em;
      font-weight: bold;
      box-shadow: 0 2px 8px #0003;
      width: auto;
      min-width: 180px;
      height: 2.5em;
      display: flex;
      align-items: center;
      justify-content: center;
    ">+ Quick Snippet</button>
  </nav>
`;

const getQuickSnippetDialog = (csrfToken) => `
  <div id="quickSnippetDialog" style="
    display: none;
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.5);
    z-index: 1000;
  ">
    <div style="
      position: absolute;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      background: #252526;
      padding: 2em;
      border-radius: 8px;
      width: 80%;
      max-width: 600px;
    ">
      <h2 style="margin-top: 0;">Quick Snippet</h2>
      <form action="/submit" method="POST" style="display: flex; flex-direction: column; gap: 1em;">
        <input type="hidden" name="_csrf" value="${csrfToken}">
        <select name="language" style="padding: 0.5em; background: #1e1e1e; color: #eee; border: 1px solid #333;">
          <option value="plaintext">Plain Text</option>
          <option value="sql">SQL</option>
          <option value="powershell">PowerShell</option>
          <option value="javascript">JavaScript</option>
          <option value="python">Python</option>
          <option value="bash">Bash</option>
        </select>
        <textarea name="snippet" style="
          height: 200px;
          padding: 0.5em;
          background: #1e1e1e;
          color: #eee;
          border: 1px solid #333;
          font-family: monospace;
        "></textarea>
        <div style="display: flex; gap: 1em; justify-content: flex-end;">
          <button type="button" id="quick-cancel-btn" style="
            padding: 0.5em 1em;
            background: #666;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
          ">Cancel</button>
          <button type="submit" style="
            padding: 0.5em 1em;
            background: #007acc;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
          ">Save</button>
        </div>
      </form>
    </div>
  </div>
  <script>
    async function refreshCsrfToken() {
      const res = await fetch('/get-csrf', { credentials: 'same-origin' });
      const data = await res.json();
      document.querySelectorAll('input[name="_csrf"]').forEach(input => {
        input.value = data.csrfToken;
      });
    }

    function showQuickSnippetDialog() {
      refreshCsrfToken().then(() => {
        document.getElementById('quickSnippetDialog').style.display = 'block';
      });
    }
    function hideQuickSnippetDialog() {
      document.getElementById('quickSnippetDialog').style.display = 'none';
    }
    document.addEventListener('DOMContentLoaded', function() {
      const quickBtn = document.getElementById('quick-snippet-btn');
      if (quickBtn) quickBtn.addEventListener('click', showQuickSnippetDialog);
      const quickCancel = document.getElementById('quick-cancel-btn');
      if (quickCancel) quickCancel.addEventListener('click', hideQuickSnippetDialog);
      const dialog = document.getElementById('quickSnippetDialog');
      if (dialog) {
        dialog.addEventListener('click', function(e) {
          if (e.target === this) hideQuickSnippetDialog();
        });
      }
    });
  </script>
`;

app.get('/', csrfProtection, (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>New Snippet</title>
      <style>
        body { font-family: 'Consolas', 'Monaco', monospace; background: #1e1e1e; color: #eee; padding: 2em; }
        .container { max-width: 900px; margin: 0 auto; }
        .snippet-window {
          background: #232323;
          border-radius: 8px;
          box-shadow: 0 4px 24px #000a;
          padding: 2em;
        }
        label { color: #aaa; font-size: 1em; margin-top: 1em; display: block; }
        #monaco-snippet { height: 300px; width: 100%; border-radius: 4px; margin-bottom: 1em; }
        select, button {
          margin: 1em 0 0.5em 0;
          padding: 0.7em 1em;
          background: #252526;
          color: #eee;
          border: 1px solid #333;
          border-radius: 4px;
          font-size: 1em;
        }
        button {
          background: #007acc;
          color: white;
          border: none;
          cursor: pointer;
        }
        .notification {
          position: fixed;
          top: 2em;
          right: 2em;
          background: #252526;
          color: #fff;
          border-radius: 6px;
          box-shadow: 0 2px 12px #000a;
          padding: 1em 2em;
          z-index: 9999;
          font-size: 1.1em;
          display: none;
          align-items: center;
          gap: 0.7em;
        }
        .notification.show {
          display: flex;
          animation: fadeIn 0.3s;
        }
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(-20px);}
          to { opacity: 1; transform: translateY(0);}
        }
      </style>
      <script src="https://cdn.jsdelivr.net/npm/monaco-editor@0.45.0/min/vs/loader.js"></script>
      <script>
        async function refreshCsrfTokenForForm(formId) {
          const res = await fetch('/get-csrf', { credentials: 'same-origin' });
          const data = await res.json();
          document.querySelectorAll(\`#\${formId} input[name="_csrf"]\`).forEach(input => {
            input.value = data.csrfToken;
          });
        }
      </script>
    </head>
    <body>
      ${getNavigation('home')}
      <div class="container">
        <div class="snippet-window">
          <h2>New Snippet</h2>
          <form id="snippet-form" autocomplete="off" spellcheck="false">
            <input type="hidden" name="_csrf" value="${req.csrfToken()}">
            <label for="language">Language:</label>
            <select name="language" id="snippet-lang">
              <option value="plaintext">Plain Text</option>
              <option value="sql">SQL</option>
              <option value="powershell">PowerShell</option>
              <option value="javascript">JavaScript</option>
              <option value="python">Python</option>
              <option value="bash">Bash</option>
            </select>
            <input type="hidden" name="snippet" id="snippet-hidden">
            <div id="monaco-snippet"></div>
            <button type="submit">💾 Save Snippet</button>
          </form>
        </div>
      </div>
      <div class="notification" id="notif"><span>✅</span><span id="notif-msg"></span></div>
      <script>
        document.addEventListener('DOMContentLoaded', function() {
          const langMap = {
            plaintext: 'plaintext',
            sql: 'sql',
            powershell: 'powershell',
            javascript: 'javascript',
            python: 'python',
            bash: 'shell'
          };
          let snippetEditor;
          require.config({ paths: { 'vs': 'https://cdn.jsdelivr.net/npm/monaco-editor@0.45.0/min/vs' }});
          require(['vs/editor/editor.main'], function () {
            snippetEditor = monaco.editor.create(document.getElementById('monaco-snippet'), {
              value: '',
              language: langMap[document.getElementById('snippet-lang').value] || 'plaintext',
              theme: 'vs-dark',
              fontSize: 16,
              minimap: { enabled: false },
              automaticLayout: true,
              scrollBeyondLastLine: false,
              roundedSelection: false,
              scrollbar: { verticalScrollbarSize: 8, horizontalScrollbarSize: 8 }
            });
            document.getElementById('snippet-lang').addEventListener('change', function() {
              const newLang = langMap[this.value] || 'plaintext';
              monaco.editor.setModelLanguage(snippetEditor.getModel(), newLang);
            });

            document.getElementById('snippet-form').addEventListener('submit', async function(e) {
              e.preventDefault();
              document.getElementById('snippet-hidden').value = snippetEditor.getValue();
              const form = e.target;
              const params = new URLSearchParams(new FormData(form));
              try {
                const res = await fetch('/submit', {
                  method: 'POST',
                  headers: { 
                    'Accept': 'application/json',
                    'Content-Type': 'application/x-www-form-urlencoded'
                  },
                  body: params,
                  credentials: 'same-origin'
                });
                if (res.ok) {
                  showNotification('Snippet saved!');
                  snippetEditor.setValue('');
                  await refreshCsrfTokenForForm('snippet-form');
                } else {
                  showNotification('Failed to save snippet', true);
                }
              } catch (err) {
                showNotification('Error: ' + err.message, true);
              }
            });

            function showNotification(msg, error) {
              const notif = document.getElementById('notif');
              notif.style.background = error ? '#ff5555' : '#252526';
              document.getElementById('notif-msg').textContent = msg;
              notif.classList.add('show');
              setTimeout(() => notif.classList.remove('show'), 2500);
            }
          });
        });
      </script>
    </body>
    </html>
  `);
});

const requireAuth = (req, res, next) => {
  if (req.session.authenticated) {
    next();
  } else {
    res.redirect('/login');
  }
};

app.get('/login', csrfProtection, (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Login</title>
      <style>
        body { font-family: monospace; background: #1e1e1e; color: #eee; padding: 2em; }
        form { max-width: 400px; margin: 0 auto; }
        input { width: 100%; padding: 0.8em; margin: 0.5em 0; background: #252526; color: #eee; border: 1px solid #333; }
        button { width: 100%; padding: 1em; background: #007acc; color: white; border: none; margin-top: 1em; }
        .error { color: #ff5555; margin-top: 1em; }
      </style>
    </head>
    <body>
      <h1>Login</h1>
      <form method="POST" action="/login">
        <input type="hidden" name="_csrf" value="${req.csrfToken()}">
        <input type="password" name="password" placeholder="Enter admin password">
        <button type="submit">Login</button>
      </form>
    </body>
    </html>
  `);
});

app.post('/login', csrfProtection, async (req, res) => {
  const correctPassword = process.env.ADMIN_PASSWORD || 'admin123';
  const hashedPassword = await bcrypt.hash(correctPassword, 10);
  
  if (await bcrypt.compare(req.body.password, hashedPassword)) {
    req.session.authenticated = true;
    res.redirect('/admin');
  } else {
    res.redirect('/login');
  }
});

app.post('/submit', csrfProtection, async (req, res) => {
  const timestamp = new Date().toISOString();
  const lang = req.body.language || 'plaintext';
  const code = req.body.snippet;
  const filename = `${timestamp}.json`;

  try {
    await pool.query(
      'INSERT INTO snippets (filename, language, code, timestamp) VALUES ($1, $2, $3, $4)',
      [filename, lang, code, timestamp]
    );
    if (req.headers.accept && req.headers.accept.includes('application/json')) {
      res.json({ success: true, message: 'Snippet saved!' });
    } else {
      res.send('✅ Snippet saved! <a href="/">Back to form</a>');
    }
  } catch (err) {
    console.error('DB insert error:', err);
    res.status(500).send('Failed to save snippet');
  }
});

app.get('/search', async (req, res) => {
  const query = req.query.q?.toLowerCase() || '';
  const language = req.query.lang?.toLowerCase();
  
  let sql = 'SELECT * FROM snippets';
  let params = [];
  let conditions = [];

  if (query) {
    conditions.push('(LOWER(code) LIKE $1 OR LOWER(filename) LIKE $1)');
    params.push(`%${query}%`);
  }
  if (language) {
    conditions.push('LOWER(language) = $' + (params.length + 1));
    params.push(language);
  }
  if (conditions.length) {
    sql += ' WHERE ' + conditions.join(' AND ');
  }
  sql += ' ORDER BY timestamp DESC';

  const { rows } = await pool.query(sql, params);
  res.json(rows);
});

app.get('/admin', requireAuth, csrfProtection, async (req, res) => {
  const { rows: snippets } = await pool.query('SELECT * FROM snippets ORDER BY timestamp DESC');
  const languages = [...new Set(snippets.map(s => s.language))];
  const snippetCount = snippets.length;
  const langCounts = languages.map(lang => ({
    lang,
    count: snippets.filter(s => s.language === lang).length
  }));

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Admin - Snippet List</title>
      <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/vs2015.min.css">
      <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
      <style>
        body { font-family: monospace; background: #1e1e1e; color: #eee; padding: 2em; }
        .container { max-width: 900px; margin: 0 auto; }
        .summary { background: #252526; padding: 1em; border-radius: 6px; margin-bottom: 2em; }
        .summary span { margin-right: 2em; }
        .search-sort { display: flex; gap: 1em; margin-bottom: 1em; }
        .search-sort input, .search-sort select { 
          padding: 0.5em; background: #252526; color: #eee; border: 1px solid #333; 
        }
        table { width: 100%; border-collapse: collapse; background: #252526; }
        th, td { padding: 0.7em; border-bottom: 1px solid #333; text-align: left; }
        th { background: #232323; }
        tr:hover { background: #2a2a2a; }
        .actions a, .actions button { margin-right: 0.5em; }
        .delete-btn { background: #ff5555; color: white; border: none; padding: 0.3em 0.7em; border-radius: 3px; cursor: pointer; }
        .delete-btn:hover { background: #ff3333; }
        .no-results { color: #ff5555; text-align: center; margin: 2em 0; }
        .action-btn {
          background: #007acc;
          color: #fff;
          border: none;
          border-radius: 4px;
          padding: 0.3em 0.9em;
          font-size: 1em;
          cursor: pointer;
          display: inline-flex;
          align-items: center;
          gap: 0.3em;
          transition: background 0.2s;
        }
        .action-btn:hover {
          background: #005fa3;
        }
        .snippet-window, .snippet-form, #monaco-snippet {
          max-width: 900px !important;
          width: 100% !important;
        }
      </style>
      <script>
        async function refreshCsrfTokenForForm(formId) {
          const res = await fetch('/get-csrf', { credentials: 'same-origin' });
          const data = await res.json();
          document.querySelectorAll(\`#\${formId} input[name="_csrf"]\`).forEach(input => {
            input.value = data.csrfToken;
          });
        }
      </script>
    </head>
    <body>
      ${getNavigation('admin')}
      <div class="container">
        <div class="summary">
          <span><strong>Total snippets:</strong> ${snippetCount}</span>
          ${langCounts.map(lc => `<span><strong>${lc.lang}:</strong> ${lc.count}</span>`).join('')}
        </div>
        <div class="search-sort">
          <input type="text" id="search" placeholder="Search snippets...">
          <select id="language">
            <option value="">All Languages</option>
            ${languages.map(lang => `<option value="${lang}">${lang}</option>`).join('')}
          </select>
          <select id="sort">
            <option value="date-desc">Newest First</option>
            <option value="date-asc">Oldest First</option>
            <option value="lang-asc">Language A-Z</option>
            <option value="lang-desc">Language Z-A</option>
          </select>
        </div>
        <table>
          <thead>
            <tr>
              <th>Filename</th>
              <th>Language</th>
              <th>Date</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="snippet-list">
            ${snippets.map(s => `
              <tr>
                <td>${s.filename}</td>
                <td>${s.language}</td>
                <td>${formatTimestamp(s.timestamp)}</td>
                <td class="actions">
                  <a href="/edit?file=${encodeURIComponent(s.filename)}">[edit]</a>
                  <a href="/view?file=${encodeURIComponent(s.filename)}" target="_blank">[view]</a>
                  <a href="#" class="delete-link" data-filename="${encodeURIComponent(s.filename)}">[delete]</a>
                  <a href="#" class="download-link" data-filename="${encodeURIComponent(s.filename)}" data-language="${s.language}">[download]</a>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
        <div id="no-results" class="no-results" style="display:none;">No snippets found.</div>
        <p><a href="/">Back to form</a></p>
      </div>
      ${getQuickSnippetDialog(req.csrfToken())}
      <form id="admin-form" style="display:none;">
        <input type="hidden" name="_csrf" value="${req.csrfToken()}">
      </form>
      <!-- Monaco Modal -->
      <div id="snippet-modal" style="display:none; position:fixed; top:0; left:0; right:0; bottom:0; background:rgba(0,0,0,0.7); z-index:2000;">
        <div style="background:#232323; border-radius:8px; max-width:800px; margin:5% auto; padding:2em; position:relative;">
          <button id="close-modal" style="position:absolute; top:1em; right:1em; background:#ff5555; color:#fff; border:none; border-radius:3px; padding:0.3em 0.7em; cursor:pointer;">✖</button>
          <h2 id="modal-title"></h2>
          <div>
            <label for="modal-language" style="color:#aaa;">Language:</label>
            <select id="modal-language" style="margin-bottom:1em;">
              <option value="plaintext">Plain Text</option>
              <option value="sql">SQL</option>
              <option value="powershell">PowerShell</option>
              <option value="javascript">JavaScript</option>
              <option value="python">Python</option>
              <option value="bash">Bash</option>
            </select>
          </div>
          <div id="monaco-modal" style="height:350px;width:100%;border-radius:4px;margin-bottom:1em;"></div>
          <div id="modal-actions" style="margin-top:1em; display:none;">
            <button id="save-edit" style="background:#007acc; color:#fff; border:none; border-radius:4px; padding:0.5em 1.2em; cursor:pointer;">Save Changes</button>
          </div>
        </div>
      </div>
      <script src="https://cdn.jsdelivr.net/npm/monaco-editor@0.45.0/min/vs/loader.js"></script>
      <script>
        let monacoInstance = null, currentEditFilename = null, isEditMode = false;
        const langMap = {
          plaintext: 'plaintext',
          sql: 'sql',
          powershell: 'powershell',
          javascript: 'javascript',
          python: 'python',
          bash: 'shell'
        };

        function showModal(title, code, language, editable) {
          document.getElementById('modal-title').textContent = title;
          document.getElementById('modal-language').value = language;
          document.getElementById('modal-language').disabled = !editable;
          document.getElementById('modal-actions').style.display = editable ? '' : 'none';
          document.getElementById('snippet-modal').style.display = 'block';
          isEditMode = editable;

          // Always clear the container before creating a new editor
          const monacoContainer = document.getElementById('monaco-modal');
          if (monacoInstance) {
            monacoInstance.dispose();
            monacoInstance = null;
          }
          monacoContainer.innerHTML = ""; // Clear previous editor DOM

          require.config({ paths: { 'vs': 'https://cdn.jsdelivr.net/npm/monaco-editor@0.45.0/min/vs' }});
          require(['vs/editor/editor.main'], function () {
            monacoInstance = monaco.editor.create(monacoContainer, {
              value: code,
              language: langMap[language] || 'plaintext',
              theme: 'vs-dark',
              fontSize: 16,
              minimap: { enabled: false },
              automaticLayout: true,
              scrollBeyondLastLine: false,
              roundedSelection: false,
              scrollbar: { verticalScrollbarSize: 8, horizontalScrollbarSize: 8 },
              readOnly: !editable,
              lineNumbers: "on"
            });
          });
        }

        document.getElementById('close-modal').onclick = () => {
          document.getElementById('snippet-modal').style.display = 'none';
          if (monacoInstance) {
            monacoInstance.dispose();
            monacoInstance = null;
          }
        };

        document.getElementById('modal-language').onchange = function() {
          if (monacoInstance) {
            monaco.editor.setModelLanguage(monacoInstance.getModel(), langMap[this.value] || 'plaintext');
          }
        };

        // Add this event listener to handle [edit] and [view] links
        document.getElementById('snippet-list').addEventListener('click', async function(event) {
          const target = event.target;
          if (target.textContent === '[edit]') {
            event.preventDefault();
            const filename = target.href.split('file=')[1];
            currentEditFilename = filename;
            // Fetch snippet data
            const res = await fetch('/snippet-raw?file=' + filename);
            const code = await res.text();
            // Fetch language
            const row = target.closest('tr');
            const language = row ? row.children[1].textContent : 'plaintext';
            showModal('Edit Snippet', code, language, true);
          }
          if (target.textContent === '[view]') {
            event.preventDefault();
            const filename = target.href.split('file=')[1];
            currentEditFilename = filename;
            const res = await fetch('/snippet-raw?file=' + filename);
            const code = await res.text();
            // Fetch language
            const row = target.closest('tr');
            const language = row ? row.children[1].textContent : 'plaintext';
            showModal('View Snippet', code, language, false);
          }
        });

        // Save changes handler for the modal
        document.getElementById('save-edit').onclick = async function() {
          if (!monacoInstance) {
            alert('Editor not ready');
            return;
          }
          const code = monacoInstance.getValue();
          const language = document.getElementById('modal-language').value;
          await refreshCsrfTokenForForm('admin-form');
          const csrfToken = document.querySelector('#admin-form input[name="_csrf"]').value;
          const params = new URLSearchParams();
          params.append('language', language);
          params.append('snippet', code);
          params.append('_csrf', csrfToken);
          const res = await fetch('/edit?file=' + encodeURIComponent(currentEditFilename), {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: params,
            credentials: 'same-origin'
          });
          if (res.redirected) {
            window.location.href = res.url; // <-- This will reload the admin page and show the updated snippet
          } else if (res.ok) {
            window.location.reload(); // fallback: reload the page to reflect changes
          } else {
            alert('Failed to save changes');
          }
        };
      </script>
    </body>
    </html>
  `);
});

app.get('/snippet-raw', requireAuth, async (req, res) => {
  const filename = req.query.file;
  if (!filename) return res.status(400).send('No file specified');
  const { rows } = await pool.query('SELECT code FROM snippets WHERE filename = $1', [filename]);
  if (!rows.length) return res.status(404).send('File not found');
  res.type('text/plain').send(rows[0].code);
});

app.post('/delete', requireAuth, csrfProtection, async (req, res) => {
  const filename = req.body.file;
  if (!filename) return res.status(400).json({ error: 'No file specified' });
  try {
    const result = await pool.query('DELETE FROM snippets WHERE filename = $1', [filename]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'File not found' });
    res.json({ success: true, message: 'File deleted successfully' });
  } catch (err) {
    console.error('Delete error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/get-csrf', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

app.get('/edit', requireAuth, csrfProtection, async (req, res) => {
  const filename = req.query.file;
  if (!filename) return res.status(400).send('No file specified');
  const { rows } = await pool.query('SELECT * FROM snippets WHERE filename = $1', [filename]);
  if (!rows.length) return res.status(404).send('File not found');
  const content = rows[0];

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Edit Snippet</title>
      <style>
        body { font-family: monospace; background: #1e1e1e; color: #eee; padding: 2em; }
        .container { max-width: 900px; margin: 0 auto; }
        .snippet-window { background: #232323; border-radius: 8px; box-shadow: 0 4px 24px #000a; padding: 2em; }
        label { color: #aaa; font-size: 1em; margin-top: 1em; display: block; }
        select, button {
          width: 100%; margin: 1em 0 0.5em 0; padding: 0.7em 1em;
          background: #252526; color: #eee; border: 1px solid #333; border-radius: 4px; font-size: 1em;
        }
        #monaco-snippet { height: 300px; width: 100%; border-radius: 4px; margin-bottom: 1em; }
        button { background: #007acc; color: white; border: none; cursor: pointer; }
      </style>
      <script src="https://cdn.jsdelivr.net/npm/monaco-editor@0.45.0/min/vs/loader.js"></script>
    </head>
    <body>
      ${getNavigation('admin')}
      <div class="container">
        <div class="snippet-window">
          <h2>Edit Snippet</h2>
          <form id="edit-form" autocomplete="off" spellcheck="false">
            <input type="hidden" name="_csrf" value="${req.csrfToken()}">
            <label for="language">Language:</label>
            <select name="language" id="snippet-lang">
              <option value="plaintext"${content.language === 'plaintext' ? ' selected' : ''}>Plain Text</option>
              <option value="sql"${content.language === 'sql' ? ' selected' : ''}>SQL</option>
              <option value="powershell"${content.language === 'powershell' ? ' selected' : ''}>PowerShell</option>
              <option value="javascript"${content.language === 'javascript' ? ' selected' : ''}>JavaScript</option>
              <option value="python"${content.language === 'python' ? ' selected' : ''}>Python</option>
              <option value="bash"${content.language === 'bash' ? ' selected' : ''}>Bash</option>
            </select>
            <input type="hidden" name="snippet" id="snippet-hidden">
            <div id="monaco-snippet"></div>
            <button type="submit">💾 Save Changes</button>
          </form>
        </div>
      </div>
      ${getQuickSnippetDialog(req.csrfToken())}
      <script>
        document.addEventListener('DOMContentLoaded', function() {
          const langMap = {
            plaintext: 'plaintext',
            sql: 'sql',
            powershell: 'powershell',
            javascript: 'javascript',
            python: 'python',
            bash: 'shell'
          };
          let snippetEditor;
          require.config({ paths: { 'vs': 'https://cdn.jsdelivr.net/npm/monaco-editor@0.45.0/min/vs' }});
          require(['vs/editor/editor.main'], function () {
            snippetEditor = monaco.editor.create(document.getElementById('monaco-snippet'), {
              value: ${JSON.stringify(content.code)},
              language: langMap["${content.language}"] || 'plaintext',
              theme: 'vs-dark',
              fontSize: 16,
              minimap: { enabled: false },
              automaticLayout: true,
              scrollBeyondLastLine: false,
              roundedSelection: false,
              scrollbar: { verticalScrollbarSize: 8, horizontalScrollbarSize: 8 }
            });
            document.getElementById('snippet-lang').addEventListener('change', function() {
              const newLang = langMap[this.value] || 'plaintext';
              monaco.editor.setModelLanguage(snippetEditor.getModel(), newLang);
            });

            document.getElementById('edit-form').addEventListener('submit', async function(e) {
              e.preventDefault();
              document.getElementById('snippet-hidden').value = snippetEditor.getValue();
              const form = e.target;
              const params = new URLSearchParams(new FormData(form));
              
              // Refresh CSRF token before submission
              await refreshCsrfTokenForForm('edit-form');
              const csrfToken = document.querySelector('#edit-form input[name="_csrf"]').value;
              params.append('_csrf', csrfToken);

              fetch('/edit?file=${encodeURIComponent(filename)}', {
                method: 'POST',
                headers: { 
                  'Accept': 'text/html,application/xhtml+xml,application/xml',
                  'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: params,
                credentials: 'same-origin'
              }).then(res => {
                if (res.redirected) {
                  window.location.href = res.url;
                } else {
                  alert('Failed to save changes');
                }
              });
            });
          });
        });
      </script>
    </body>
    </html>
  `);
});

app.post('/edit', requireAuth, csrfProtection, async (req, res) => {
  const filename = req.query.file;
  if (!filename) return res.status(400).send('No file specified');
  try {
    await pool.query(
      'UPDATE snippets SET language = $1, code = $2 WHERE filename = $3',
      [req.body.language, req.body.snippet, filename]
    );
    res.redirect('/admin');
  } catch (err) {
    res.status(500).send('Failed to update snippet');
  }
});

app.get('/view', requireAuth, async (req, res) => {
  const filename = req.query.file;
  if (!filename) return res.status(400).send('No file specified');
  const { rows } = await pool.query('SELECT * FROM snippets WHERE filename = $1', [filename]);
  if (!rows.length) return res.status(404).send('File not found');
  const content = rows[0];

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>View Snippet - ${filename}</title>
      <style>
        body { font-family: monospace; background: #1e1e1e; color: #eee; padding: 2em; }
        .container { max-width: 900px; margin: 0 auto; }
        .snippet-window { background: #232323; border-radius: 8px; box-shadow: 0 4px 24px #000a; padding: 2em; }
        #monaco-viewer { height: 400px; width: 100%; border-radius: 4px; margin-bottom: 1em; }
        h2 { margin-top: 0; }
        a { color: #7ecfff; }
      </style>
      <script src="https://cdn.jsdelivr.net/npm/monaco-editor@0.45.0/min/vs/loader.js"></script>
    </head>
    <body>
      ${getNavigation('admin')}
      <div class="container">
        <div class="snippet-window">
          <h2>${filename}</h2>
          <p><strong>Language:</strong> ${content.language}</p>
          <div id="monaco-viewer"></div>
          <p><a href="/admin">Back to Admin</a></p>
        </div>
      </div>
      <script>
        document.addEventListener('DOMContentLoaded', function() {
          const langMap = {
            plaintext: 'plaintext',
            sql: 'sql',
            powershell: 'powershell',
            javascript: 'javascript',
            python: 'python',
            bash: 'shell'
          };
          require.config({ paths: { 'vs': 'https://cdn.jsdelivr.net/npm/monaco-editor@0.45.0/min/vs' }});
          require(['vs/editor/editor.main'], function () {
            monaco.editor.create(document.getElementById('monaco-viewer'), {
              value: ${JSON.stringify(content.code)},
              language: langMap["${content.language}"] || 'plaintext',
              theme: 'vs-dark',
              fontSize: 16,
              minimap: { enabled: false },
              automaticLayout: true,
              scrollBeyondLastLine: false,
              roundedSelection: false,
              scrollbar: { verticalScrollbarSize: 8, horizontalScrollbarSize: 8 },
              readOnly: true,
              lineNumbers: "on"
            });
          });
        });
      </script>
    </body>
    </html>
  `);
});

function formatTimestamp(ts) {
  if (!ts) return '';
  if (ts instanceof Date) ts = ts.toISOString();
  return ts.replace(/T/, ' ').replace(/-/g, '/').slice(0, 19);
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
console.log('Admin JS loaded');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // Vercel env var
  ssl: { rejectUnauthorized: false } // Neon requires SSL
});

// Example: test connection
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('Postgres connection error:', err);
  } else {
    console.log('Postgres connected:', res.rows[0]);
  }
});
