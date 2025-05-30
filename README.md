# Snippet Manager

A full-stack web application for managing code snippets, built with Node.js and Express.

## Features

- Submit code snippets with language selection
- Syntax highlighting using highlight.js
- Markdown rendering for snippets
- Admin interface for managing snippets
- Password protection for admin routes
- Live preview while editing
- Responsive dark theme UI

## Setup

1. Install dependencies:
   ```bash
   npm install
   ```

2. Set environment variables (optional):
   ```bash
   export ADMIN_PASSWORD=your-secure-password
   export SESSION_SECRET=your-session-secret
   ```

3. Start the server:
   ```bash
   node index.js
   ```

The server will run on port 3000 by default. You can change this by setting the `PORT` environment variable.

## Routes

- `/` - Main form for submitting snippets
- `/admin` - Admin interface (password protected)
- `/edit?file=filename.md` - Edit a specific snippet
- `/view?file=filename.md` - View a specific snippet
- `/login` - Admin login page

## Security Notes

- Change the default admin password in production
- Set a secure session secret in production
- Consider using HTTPS in production

## Directory Structure

```
/
├── public/
│   └── form.html
├── snippets/
│   └── [timestamp].md
├── index.js
├── package.json
└── README.md
```

## Dependencies

- express
- body-parser
- express-session
- bcrypt
- marked
- highlight.js
