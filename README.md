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
- REST API for programmatic access

## Setup

1. Install dependencies:
   ```bash
   npm install
   ```

2. Set environment variables (optional):
   ```bash
   export ADMIN_PASSWORD=your-secure-password
   export SESSION_SECRET=your-session-secret
   export API_KEY=your-api-key
   ```

3. Start the server:
   ```bash
   node index.js
   ```

The server will run on port 3000 by default. You can change this by setting the `PORT` environment variable.

## Getting an API Key

To get an API key:

1. Log in to the admin interface at `/admin`
2. Visit `/generate-api-key` to generate a new API key
3. Copy the generated key and set it in your environment:
   ```bash
   export API_KEY=your-generated-key
   ```
   Or add it to your `.env` file:
   ```
   API_KEY=your-generated-key
   ```

⚠️ The API key will only be shown once when generated. Make sure to copy it immediately!

## Web Interface Routes

- `/` - Main form for submitting snippets
- `/admin` - Admin interface (password protected)
- `/edit?file=filename.md` - Edit a specific snippet
- `/view?file=filename.md` - View a specific snippet
- `/login` - Admin login page

## REST API

The API requires an API key to be passed in the `X-API-Key` header for all requests.

### Authentication

All API requests must include the `X-API-Key` header:
```bash
X-API-Key: your-api-key
```

### Endpoints

#### Create a Snippet
```bash
POST /api/snippets
Content-Type: application/json
X-API-Key: your-api-key

{
    "language": "python",
    "code": "print('Hello, World!')"
}
```

Response (201 Created):
```json
{
    "success": true,
    "message": "Snippet created successfully",
    "data": {
        "filename": "2024-03-21T12:34:56.789Z.json",
        "language": "python",
        "timestamp": "2024-03-21T12:34:56.789Z"
    }
}
```

#### List All Snippets
```bash
GET /api/snippets
X-API-Key: your-api-key
```

Response (200 OK):
```json
[
    {
        "filename": "2024-03-21T12:34:56.789Z.json",
        "language": "python",
        "code": "print('Hello, World!')",
        "timestamp": "2024-03-21T12:34:56.789Z"
    }
]
```

#### Get a Specific Snippet
```bash
GET /api/snippets/:filename
X-API-Key: your-api-key
```

Response (200 OK):
```json
{
    "filename": "2024-03-21T12:34:56.789Z.json",
    "language": "python",
    "code": "print('Hello, World!')",
    "timestamp": "2024-03-21T12:34:56.789Z"
}
```

#### Delete a Snippet
```bash
DELETE /api/snippets/:filename
X-API-Key: your-api-key
```

Response (200 OK):
```json
{
    "success": true,
    "message": "Snippet deleted successfully"
}
```

### Error Responses

All endpoints may return the following error responses:

- 400 Bad Request:
```json
{
    "error": "Missing required fields",
    "required": ["language", "code"]
}
```

- 401 Unauthorized:
```json
{
    "error": "Invalid API key"
}
```

- 404 Not Found:
```json
{
    "error": "Snippet not found"
}
```

- 500 Server Error:
```json
{
    "error": "Failed to create snippet",
    "details": "Error message"
}
```

## Security Notes

- Change the default admin password in production
- Set a secure session secret in production
- Set a secure API key in production
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
