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

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrcElem: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
      imgSrc: ["'self'", "data:", "https://cdnjs.cloudflare.com"], // Added data: for potential inline images if needed
      connectSrc: ["'self'"],
      fontSrc: ["'self'", "https://cdnjs.cloudflare.com"],
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

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Admin - Snippet List</title>
      <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/vs2015.min.css">
      <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
      <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/javascript.min.js"></script>
      <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/python.min.js"></script>
      <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/sql.min.js"></script>
      <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/powershell.min.js"></script>
      <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/bash.min.js"></script>
      <style>
        body { font-family: monospace; background: #1e1e1e; color: #eee; padding: 2em; }
        .container { max-width: 800px; margin: 0 auto; }
        .search-box { margin-bottom: 2em; }
        .search-box input, .search-box select { 
          padding: 0.5em; 
          margin-right: 1em; 
          background: #252526; 
          color: #eee; 
          border: 1px solid #333; 
        }
        ul { list-style: none; padding: 0; }
        li { margin: 0.5em 0; display: flex; justify-content: space-between; align-items: center; }
        a { color: #007acc; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .actions { margin-left: 1em; }
        .delete-btn { 
          background: #ff5555; 
          color: white; 
          border: none; 
          padding: 0.3em 0.6em; 
          cursor: pointer; 
          border-radius: 3px; 
        }
        .delete-btn:hover { background: #ff3333; }
        .snippet-preview {
          margin-top: 0.5em;
          padding: 0.5em;
          background: #252526;
          border-radius: 4px;
          font-size: 0.9em;
          max-height: 100px;
          overflow: hidden;
        }
        .snippet-preview pre {
          margin: 0;
          padding: 0;
        }
      </style>
    </head>
    <body>
      ${getNavigation('admin')}
      <div class="container">
        <h1>Snippet List</h1>
        <div class="search-box">
          <input type="text" id="search" placeholder="Search snippets...">
          <select id="language">
            <option value="">All Languages</option>
            ${languages.map(lang => `<option value="${lang}">${lang}</option>`).join('')}
          </select>
        </div>
        <ul id="snippet-list">
          ${snippets.map(s => `
            <li>
              <div>
                <span>${s.filename}</span>
                <div class="snippet-preview">
                  <pre><code class="hljs language-${s.language}">${s.content}</code></pre>
                </div>
              </div>
              <div class="actions">
                <a href="/edit?file=${s.filename}">[edit]</a>
                <a href="/view?file=${s.filename}" target="_blank">[view]</a>
                <button class="delete-btn" data-filename="${s.filename}">[delete]</button>
              </div>
            </li>
          `).join('')}
        </ul>
        <p><a href="/">Back to form</a></p>
      </div>
      ${getQuickSnippetDialog(req.csrfToken())}
      <script>
        const searchInput = document.getElementById('search');
        const languageSelect = document.getElementById('language');
        const snippetList = document.getElementById('snippet-list');

        // Initialize syntax highlighting
        document.addEventListener('DOMContentLoaded', (event) => {
          document.querySelectorAll('pre code').forEach((block) => {
            hljs.highlightElement(block);
          });
        });

        async function updateList() {
          const query = searchInput.value;
          const language = languageSelect.value;
          const response = await fetch('/search?q=' + encodeURIComponent(query) + '&lang=' + encodeURIComponent(language));
          const snippets = await response.json();
          
          snippetList.innerHTML = snippets.map(function(s) {
            return '<li>' +
              '<div>' +
                '<span>' + s.filename + '</span>' +
                '<div class="snippet-preview">' +
                  '<pre><code class="hljs language-' + s.language + '">' + s.content + '</code></pre>' +
                '</div>' +
              '</div>' +
              '<div class="actions">' +
                '<a href="/edit?file=' + encodeURIComponent(s.filename) + '">[edit]</a>' +
                '<a href="/view?file=' + encodeURIComponent(s.filename) + '" target="_blank">[view]</a>' +
                '<button class="delete-btn" data-filename="' + encodeURIComponent(s.filename) + '">[delete]</button>' +
              '</div>' +
            '</li>';
          }).join('');

          // Re-initialize syntax highlighting for new content
          document.querySelectorAll('pre code').forEach((block) => {
            hljs.highlightElement(block);
          });
        }

        searchInput.addEventListener('input', updateList);
        languageSelect.addEventListener('change', updateList);

        // Use event delegation for delete button clicks
        snippetList.addEventListener('click', async (event) => {
          const target = event.target;
          if (target.classList.contains('delete-btn')) {
            event.preventDefault(); // Prevent default action
            const filename = target.dataset.filename;
            console.log('Delete button clicked for:', filename);
            if (confirm('Are you sure you want to delete this snippet?')) {
              console.log('User confirmed deletion, sending request...');
              const response = await fetch('/delete?file=' + encodeURIComponent(filename), {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  // Ensure the CSRF token is correctly included
                  'X-CSRF-Token': document.querySelector('input[name="_csrf"]').value
                }
              });
              if (response.ok) {
                console.log('Delete request successful, updating list...');
                updateList();
              } else {
                console.error('Delete request failed:', response.status, response.statusText);
                const errorText = await response.text();
                console.error('Error details:', errorText);
                alert('Failed to delete snippet: ' + response.statusText + (errorText ? ' - ' + errorText : ''));
              }
            }
          }
        });
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
  const code = content.code;

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Edit Snippet</title>
      <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/vs2015.min.css">
      <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
      <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/javascript.min.js"></script>
      <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/python.min.js"></script>
      <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/sql.min.js"></script>
      <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/powershell.min.js"></script>
      <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/bash.min.js"></script>
      <style>
        body { font-family: monospace; background: #1e1e1e; color: #eee; padding: 2em; }
        .container { max-width: 1200px; margin: 0 auto; }
        textarea, select { width: 100%; margin: 1em 0; padding: 1em; background: #252526; color: #eee; border: 1px solid #333; }
        textarea { height: 300px; }
        button { padding: 1em 2em; background: #007acc; color: white; border: none; cursor: pointer; }
        .preview { margin-top: 2em; padding: 1em; background: #252526; border: 1px solid #333; }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>Editing: ${filename}</h1>
        <form method="POST" action="/save-edit">
          <input type="hidden" name="filename" value="${filename}">
          <select name="language" onchange="updatePreview()">
            <option value="plaintext" ${lang === 'plaintext' ? 'selected' : ''}>Plain Text</option>
            <option value="sql" ${lang === 'sql' ? 'selected' : ''}>SQL</option>
            <option value="powershell" ${lang === 'powershell' ? 'selected' : ''}>PowerShell</option>
            <option value="javascript" ${lang === 'javascript' ? 'selected' : ''}>JavaScript</option>
            <option value="python" ${lang === 'python' ? 'selected' : ''}>Python</option>
            <option value="bash" ${lang === 'bash' ? 'selected' : ''}>Bash</option>
          </select>
          <textarea name="snippet" oninput="updatePreview()">${code}</textarea>
          <button type="submit">Save Changes</button>
        </form>
        <div class="preview">
          <h3>Preview:</h3>
          <pre><code id="preview"></code></pre>
        </div>
      </div>
      <script>
        function updatePreview() {
          const language = document.querySelector('select[name="language"]').value;
          const code = document.querySelector('textarea[name="snippet"]').value;
          const preview = document.getElementById('preview');
          preview.textContent = code;
          preview.className = 'hljs language-' + language;
          hljs.highlightElement(preview);
        }
        updatePreview();
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
      <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
      <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/sql.min.js"></script>
      <style>
        body { 
          font-family: 'Consolas', 'Monaco', monospace; 
          background: #1e1e1e; 
          color: #eee; 
          padding: 2em;
          line-height: 1.6;
        }
        .container { 
          max-width: 800px; 
          margin: 0 auto; 
        }
        pre {
          background: #1e1e1e;
          padding: 1em;
          border-radius: 4px;
          overflow-x: auto;
          position: relative;
          margin: 1em 0;
        }
        code {
          font-family: 'Consolas', 'Monaco', monospace;
          font-size: 14px;
          line-height: 1.5;
          tab-size: 4;
          white-space: pre;
        }
        .line-numbers {
          position: absolute;
          left: 0;
          top: 0;
          bottom: 0;
          width: 3.5em;
          background: #252526;
          border-right: 1px solid #333;
          padding: 1em 0.5em;
          text-align: right;
          color: #666;
          user-select: none;
        }
        .code-content {
          margin-left: 3.5em;
          padding: 1em;
        }
        .hljs {
          background: transparent !important;
          padding: 0 !important;
        }
        .hljs-keyword { color: #569cd6; }
        .hljs-string { color: #ce9178; }
        .hljs-number { color: #b5cea8; }
        .hljs-comment { color: #6a9955; }
        .hljs-function { color: #dcdcaa; }
        .hljs-variable { color: #9cdcfe; }
        .hljs-operator { color: #d4d4d4; }
        .hljs-attr { color: #9cdcfe; }
        .hljs-property { color: #9cdcfe; }
        .hljs-selector { color: #d7ba7d; }
        .hljs-tag { color: #569cd6; }
        .hljs-attribute { color: #9cdcfe; }
      </style>
    </head>
    <body>
      ${getNavigation('view')}
      <div class="container">
        <h1>${filename}</h1>
        <pre><code class="hljs language-sql">${code}</code></pre>
      </div>
      <script>
        // Initialize syntax highlighting and line numbers
        document.addEventListener('DOMContentLoaded', (event) => {
          const pre = document.querySelector('pre');
          const code = pre ? pre.querySelector('code') : null;

          if (pre && code) {
            // Store the original code content and language before restructuring
            const originalCode = code.textContent;
            // Extract language from the class name (e.g., 'language-sql' -> 'sql')
            const langMatch = code.className.match(/language-(.+)/);
            const lang = langMatch ? langMatch[1] : 'plaintext';

            // Add line numbers
            const lines = originalCode.split('\n');
            const lineNumbers = document.createElement('div');
            lineNumbers.className = 'line-numbers';
            lineNumbers.innerHTML = lines.map((_, i) => i + 1).join('\n');

            const codeContent = document.createElement('div');
            codeContent.className = 'code-content';

            // Create a new code element, set its content, and add highlight.js classes
            const newCodeElement = document.createElement('code');
            newCodeElement.textContent = originalCode;
            newCodeElement.classList.add('hljs', 'language-' + lang);

            // Append the new code element to the content wrapper
            codeContent.appendChild(newCodeElement);

            // Clear the original pre and append the new structure
            pre.innerHTML = '';
            pre.appendChild(lineNumbers);
            pre.appendChild(codeContent);

            // Apply syntax highlighting to the new code element
            console.log('Attempting to highlight new code element:', newCodeElement);
            hljs.highlightElement(newCodeElement);

          } else {
            console.error('Pre or code element not found on view page.');
          }
        });
      </script>
    </body>
    </html>
  `);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
