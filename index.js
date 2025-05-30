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

const app = express();

// Trust proxy headers for accurate IP detection in rate limiting
app.set('trust proxy', 1);

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrcElem: [
        "'self'",
        "'unsafe-inline'",
        "https://cdnjs.cloudflare.com",
        "https://cdn.jsdelivr.net"
      ],
      scriptSrc: [
        "'self'",
        "'unsafe-inline'",
        "https://cdnjs.cloudflare.com",
        "https://cdn.jsdelivr.net"
      ],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net"],
      imgSrc: ["'self'", "data:", "https://cdnjs.cloudflare.com"],
      connectSrc: ["'self'", "https://cdn.jsdelivr.net"],
      fontSrc: ["'self'", "https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
}));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

// Session middleware must come before CSRF
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// CSRF protection
const csrfProtection = csrf({ 
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production'
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    // Handle CSRF token errors
    res.status(403).send('CSRF token validation failed');
  } else {
    console.error(err.stack);
    res.status(500).send('Something broke!');
  }
});

// Configure marked for syntax highlighting
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

// Ensure snippets directory exists
const snippetsDir = path.join(__dirname, 'snippets');
if (!fs.existsSync(snippetsDir)) {
  fs.mkdirSync(snippetsDir);
}

// Helper function to get all snippets
const getAllSnippets = () => {
  return fs.readdirSync(snippetsDir)
    .filter(f => f.endsWith('.json'))
    .map(filename => {
      const content = JSON.parse(fs.readFileSync(path.join(snippetsDir, filename), 'utf-8'));
      return {
        filename,
        language: content.language || 'plaintext',
        content: content.code,
        timestamp: filename.replace('.json', '')
      };
    })
    .sort((a, b) => b.timestamp.localeCompare(a.timestamp));
};

// Helper function to generate navigation HTML
const getNavigation = (currentPage) => `
  <nav style="
    background: #252526;
    padding: 1em;
    margin-bottom: 2em;
    border-bottom: 1px solid #333;
    display: flex;
    justify-content: space-between;
    align-items: center;
  ">
    <div>
      <a href="/" style="color: #007acc; text-decoration: none; margin-right: 1em;">Home</a>
      <a href="/admin" style="color: #007acc; text-decoration: none;">Admin</a>
    </div>
    <button onclick="showQuickSnippetDialog()" style="
      background: #007acc;
      color: white;
      border: none;
      padding: 0.5em 1em;
      border-radius: 4px;
      cursor: pointer;
    ">Quick Snippet</button>
  </nav>
`;

// Helper function to generate quick snippet dialog HTML
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
          <button type="button" onclick="hideQuickSnippetDialog()" style="
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
    function showQuickSnippetDialog() {
      document.getElementById('quickSnippetDialog').style.display = 'block';
    }
    function hideQuickSnippetDialog() {
      document.getElementById('quickSnippetDialog').style.display = 'none';
    }
    // Close dialog when clicking outside
    document.getElementById('quickSnippetDialog').addEventListener('click', function(e) {
      if (e.target === this) {
        hideQuickSnippetDialog();
      }
    });
  </script>
`;

// Root route - serve the form
app.get('/', csrfProtection, (req, res) => {
  const formHtml = fs.readFileSync(path.join(__dirname, 'public', 'form.html'), 'utf-8');
  const html = formHtml
    .replace('{{csrfToken}}', req.csrfToken())
    .replace('</body>', `${getQuickSnippetDialog(req.csrfToken())}</body>`)
    .replace('<body>', '<body>' + getNavigation('home'));
  res.send(html);
});

// Password protection middleware
const requireAuth = (req, res, next) => {
  if (req.session.authenticated) {
    next();
  } else {
    res.redirect('/login');
  }
};

// Login page
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

// Login handler
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

// Submit snippet
app.post('/submit', csrfProtection, (req, res) => {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const lang = req.body.language || 'plaintext';
  const code = req.body.snippet;
  const filename = `${timestamp}.json`;
  const filepath = path.join(snippetsDir, filename);

  const content = {
    language: lang,
    code: code,
    timestamp: timestamp
  };
  
  fs.writeFileSync(filepath, JSON.stringify(content, null, 2));
  res.send('✅ Snippet saved! <a href="/">Back to form</a>');
});

// Search snippets
app.get('/search', (req, res) => {
  const query = req.query.q?.toLowerCase() || '';
  const language = req.query.lang?.toLowerCase();
  
  const snippets = getAllSnippets().filter(snippet => {
    const matchesQuery = query === '' || 
      snippet.content.toLowerCase().includes(query) ||
      snippet.filename.toLowerCase().includes(query);
    const matchesLanguage = !language || snippet.language.toLowerCase() === language;
    return matchesQuery && matchesLanguage;
  });

  res.json(snippets);
});

// Admin page
app.get('/admin', requireAuth, csrfProtection, (req, res) => {
  const snippets = getAllSnippets();
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
      </style>
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
                <td>${s.timestamp.replace(/T/, ' ').replace(/-/g, '/').slice(0, 19)}</td>
                <td class="actions">
                  <a href="/edit?file=${s.filename}">[edit]</a>
                  <a href="/view?file=${s.filename}" target="_blank">[view]</a>
                  <button class="delete-btn" data-filename="${s.filename}">[delete]</button>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
        <div id="no-results" class="no-results" style="display:none;">No snippets found.</div>
        <p><a href="/">Back to form</a></p>
      </div>
      ${getQuickSnippetDialog(req.csrfToken())}
      <script>
        const searchInput = document.getElementById('search');
        const languageSelect = document.getElementById('language');
        const sortSelect = document.getElementById('sort');
        const snippetList = document.getElementById('snippet-list');
        const noResults = document.getElementById('no-results');

        async function updateList() {
          const query = searchInput.value;
          const language = languageSelect.value;
          const response = await fetch('/search?q=' + encodeURIComponent(query) + '&lang=' + encodeURIComponent(language));
          let snippets = await response.json();

          // Sorting
          const sort = sortSelect.value;
          snippets = snippets.sort((a, b) => {
            if (sort === 'date-desc') return b.timestamp.localeCompare(a.timestamp);
            if (sort === 'date-asc') return a.timestamp.localeCompare(b.timestamp);
            if (sort === 'lang-asc') return a.language.localeCompare(b.language);
            if (sort === 'lang-desc') return b.language.localeCompare(a.language);
            return 0;
          });

          if (snippets.length === 0) {
            snippetList.innerHTML = '';
            noResults.style.display = '';
          } else {
            noResults.style.display = 'none';
            snippetList.innerHTML = snippets.map(function(s) {
              return '<tr>' +
                '<td>' + s.filename + '</td>' +
                '<td>' + s.language + '</td>' +
                '<td>' + s.timestamp.replace(/T/, ' ').replace(/-/g, '/').slice(0, 19) + '</td>' +
                '<td class="actions">' +
                  '<a href="/edit?file=' + encodeURIComponent(s.filename) + '">[edit]</a>' +
                  '<a href="/view?file=' + encodeURIComponent(s.filename) + '" target="_blank">[view]</a>' +
                  '<button class="delete-btn" data-filename="' + encodeURIComponent(s.filename) + '">[delete]</button>' +
                '</td>' +
              '</tr>';
            }).join('');
          }
        }

        searchInput.addEventListener('input', updateList);
        languageSelect.addEventListener('change', updateList);
        sortSelect.addEventListener('change', updateList);

        // Delete handler
        snippetList.addEventListener('click', async (event) => {
          const target = event.target;
          if (target.classList.contains('delete-btn')) {
            event.preventDefault();
            const filename = target.dataset.filename;
            if (confirm('Are you sure you want to delete this snippet?')) {
              const response = await fetch('/delete?file=' + encodeURIComponent(filename), {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  'X-CSRF-Token': document.querySelector('input[name="_csrf"]').value
                }
              });
              if (response.ok) updateList();
              else alert('Failed to delete snippet.');
            }
          }
        });

        // Initial load
        updateList();
      </script>
    </body>
    </html>
  `);
});

// Delete snippet
app.post('/delete', requireAuth, csrfProtection, (req, res) => {
  console.log('Delete route received request for file:', req.query.file);
  const filename = req.query.file;
  if (!filename) {
    console.error('Delete route: No file specified');
    return res.status(400).send('No file specified');
  }
  
  const filepath = path.join(snippetsDir, filename);
  if (!fs.existsSync(filepath)) {
    console.error('Delete route: File not found', filepath);
    return res.status(404).send('File not found');
  }
  
  try {
    fs.unlinkSync(filepath);
    console.log('Successfully deleted file:', filepath);
    res.sendStatus(200);
  } catch (error) {
    console.error('Error deleting file:', filepath, error);
    res.status(500).send('Failed to delete file');
  }
});

// Edit page
app.get('/edit', requireAuth, (req, res) => {
  const filename = req.query.file;
  if (!filename) return res.status(400).send('No file specified');
  const fullPath = path.join(snippetsDir, filename);
  if (!fs.existsSync(fullPath)) return res.status(404).send('File not found');
  const content = JSON.parse(fs.readFileSync(fullPath, 'utf-8'));
  const lang = content.language || 'plaintext';
  const code = content.code.replace(/<\/script>/g, '<\\/script>'); // Prevent script tag break

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Edit Snippet</title>
      <style>
        body { font-family: 'Consolas', 'Monaco', monospace; background: #1e1e1e; color: #eee; padding: 2em; }
        .container { max-width: 1200px; margin: 0 auto; }
        .editor-window {
          background: #1e1e1e;
          border: 1px solid #333;
          border-radius: 8px 8px 0 0;
          box-shadow: 0 4px 24px #000a;
          margin-bottom: 2em;
        }
        .editor-header {
          background: #232323;
          border-bottom: 1px solid #333;
          border-radius: 8px 8px 0 0;
          padding: 0.5em 1em;
          display: flex;
          align-items: center;
          gap: 0.5em;
        }
        .editor-dot { width: 12px; height: 12px; border-radius: 50%; display: inline-block; }
        .dot-red { background: #ff5f56; }
        .dot-yellow { background: #ffbd2e; }
        .dot-green { background: #27c93f; }
        .editor-title { margin-left: 1em; color: #bbb; font-size: 1em; flex: 1; }
        .editor-label { color: #aaa; font-size: 0.95em; margin-top: 1em; }
        #monaco { height: 400px; width: 100%; border-radius: 0 0 8px 8px; margin-bottom: 1em; }
        form { margin-bottom: 0; }
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
      </style>
      <script src="https://cdn.jsdelivr.net/npm/monaco-editor@0.45.0/min/vs/loader.js"></script>
    </head>
    <body>
      <div class="container">
        <div class="editor-window">
          <div class="editor-header">
            <span class="editor-dot dot-red"></span>
            <span class="editor-dot dot-yellow"></span>
            <span class="editor-dot dot-green"></span>
            <span class="editor-title">${filename}</span>
          </div>
          <label class="editor-label" for="lang-select">Language:</label>
          <select name="language" id="lang-select" style="width:200px;">
            <option value="plaintext" ${lang === 'plaintext' ? 'selected' : ''}>Plain Text</option>
            <option value="sql" ${lang === 'sql' ? 'selected' : ''}>SQL</option>
            <option value="powershell" ${lang === 'powershell' ? 'selected' : ''}>PowerShell</option>
            <option value="javascript" ${lang === 'javascript' ? 'selected' : ''}>JavaScript</option>
            <option value="python" ${lang === 'python' ? 'selected' : ''}>Python</option>
            <option value="bash" ${lang === 'bash' ? 'selected' : ''}>Bash</option>
          </select>
          <div id="monaco"></div>
          <form method="POST" action="/save-edit" autocomplete="off" spellcheck="false" onsubmit="return submitMonaco()">
            <input type="hidden" name="filename" value="${filename}">
            <input type="hidden" name="language" id="hidden-language" value="${lang}">
            <input type="hidden" name="snippet" id="snippet-hidden">
            <button type="submit">💾 Save Changes</button>
          </form>
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
          let editor;
          require.config({ paths: { 'vs': 'https://cdn.jsdelivr.net/npm/monaco-editor@0.45.0/min/vs' }});
          require(['vs/editor/editor.main'], function () {
            editor = monaco.editor.create(document.getElementById('monaco'), {
              value: \`${code.replace(/\\/g, '\\\\').replace(/`/g, '\\`')}\`,
              language: langMap['${lang}'] || 'plaintext',
              theme: 'vs-dark',
              fontSize: 16,
              minimap: { enabled: false },
              automaticLayout: true,
              scrollBeyondLastLine: false,
              roundedSelection: false,
              scrollbar: { verticalScrollbarSize: 8, horizontalScrollbarSize: 8 }
            });
            document.getElementById('lang-select').addEventListener('change', function() {
              const newLang = langMap[this.value] || 'plaintext';
              monaco.editor.setModelLanguage(editor.getModel(), newLang);
              document.getElementById('hidden-language').value = this.value;
            });
            window.submitMonaco = function() {
              document.getElementById('snippet-hidden').value = editor.getValue();
              document.getElementById('hidden-language').value = document.getElementById('lang-select').value;
              return true;
            }
          });
        });
      </script>
    </body>
    </html>
  `);
});

// Save edit
app.post('/save-edit', requireAuth, (req, res) => {
  const { filename, language, snippet } = req.body;
  if (!filename) return res.status(400).send('Missing filename');

  const content = {
    language: language,
    code: snippet,
    timestamp: filename.replace('.json', '')
  };
  
  const fullPath = path.join(snippetsDir, filename);
  fs.writeFileSync(fullPath, JSON.stringify(content, null, 2));
  res.redirect('/admin');
});

// View snippet
app.get('/view', (req, res) => {
  const filename = req.query.file;
  if (!filename) return res.status(400).send('No file specified');
  
  const fullPath = path.join(snippetsDir, filename);
  if (!fs.existsSync(fullPath)) return res.status(404).send('File not found');

  const content = JSON.parse(fs.readFileSync(fullPath, 'utf-8'));
  const lang = content.language || 'plaintext';
  const code = content.code;

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>${filename}</title>
      <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/vs2015.min.css">
      <style>
        body { font-family: 'Consolas', 'Monaco', monospace; background: #1e1e1e; color: #eee; padding: 2em; }
        .container { max-width: 900px; margin: 0 auto; }
        .code-block { background: #1e1e1e; border: 1px solid #333; border-radius: 4px; display: flex; }
        .line-numbers {
          background: #232323;
          color: #444;
          padding: 1em 0.5em;
          text-align: right;
          user-select: none;
          min-width: 3em;
          border-right: 1px solid #333;
        }
        .code-content {
          padding: 1em;
          overflow-x: auto;
          width: 100%;
        }
        .hljs {
          background: transparent !important;
        }
      </style>
      <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
      <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/javascript.min.js"></script>
      <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/python.min.js"></script>
      <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/sql.min.js"></script>
      <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/powershell.min.js"></script>
      <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/bash.min.js"></script>
    </head>
    <body>
      ${getNavigation('view')}
      <div class="container">
        <h1>${filename}</h1>
        <div class="code-block">
          <div class="line-numbers" id="line-numbers"></div>
          <div class="code-content">
            <pre style="margin:0;"><code id="code" class="hljs language-${lang}"></code></pre>
          </div>
        </div>
      </div>
      <script>
        function escapeHtml(text) {
          return text.replace(/[&<>"']/g, function(m) {
            return ({
              '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
            })[m];
          });
        }
        document.addEventListener('DOMContentLoaded', function() {
          const code = \`${code.replace(/`/g, '\\`')}\`;
          const lines = code.split('\\n');
          document.getElementById('line-numbers').innerHTML = lines.map((_, i) => i + 1).join('<br>');
          const codeElem = document.getElementById('code');
          codeElem.textContent = code;
          hljs.highlightElement(codeElem);
        });
      </script>
    </body>
    </html>
  `);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
