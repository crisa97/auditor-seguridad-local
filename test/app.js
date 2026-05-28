const crypto = require('crypto')
const escapeHtml = require('escape-html')
const express = require('express')
const rateLimit = require('express-rate-limit')
const sqlite3 = require('sqlite3').verbose()
const bodyParser = require('body-parser')
const jwt = require('jsonwebtoken')
const path = require('path')

const app = express()
const PORT = 3000

app.use(bodyParser.urlencoded({ extended: true }))
app.use(bodyParser.json())

// ——— Rate limiting ———
const isTest = process.env.NODE_ENV === 'test'
const limiter15 = isTest
  ? (req, res, next) => next()
  : rateLimit({
      windowMs: 15 * 60 * 1000,
      max: 100,
      standardHeaders: true,
      legacyHeaders: true,
      message: { error: 'Demasiadas peticiones. Intenta de nuevo en 15 minutos.' },
    })

// ——— Database init ———
const dbPath = path.join(__dirname, 'database.db')
const db = new sqlite3.Database(dbPath)

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT,
      password TEXT,
      role TEXT
    )
  `)

  db.run(`
    CREATE TABLE IF NOT EXISTS notes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT,
      content TEXT,
      owner TEXT
    )
  `)

  const stmt = db.prepare('SELECT COUNT(*) AS cnt FROM users WHERE username = ?')
  stmt.get('admin', (err, row) => {
    if (!err && row.cnt === 0) {
      db.run("INSERT INTO users(username, password, role) VALUES (?, ?, ?)",
        ['admin', 'admin123', 'admin'])
    }
  })
  stmt.finalize()
})

// ——— POST /login (SQL injection fix + rate limit) ———
app.post('/login', limiter15, (req, res) => {
  const { username, password } = req.body

  const query = 'SELECT * FROM users WHERE username = ? AND password = ?'
  const safePrefix = '[LOGIN QUERY redacted]'
  console.log(safePrefix)

  db.get(query, [username, password], (err, user) => {
    if (err) {
      console.error('Login query error:', err.message)
      return res.status(500).json({ error: 'Error interno del servidor' })
    }

    if (!user) {
      return res.status(401).send('Credenciales inválidas')
    }

    const token = jwt.sign(
      {
        username: user.username,
        role: user.role
      },
      process.env.JWT_SECRET || 'secret123'
    )

    res.json({
      message: 'Login exitoso',
      token
    })
  })
})

// ——— POST /notes (rate limit) ———
app.post('/notes', limiter15, (req, res) => {
  const { title, content, owner } = req.body

  db.run(
    'INSERT INTO notes(title, content, owner) VALUES (?, ?, ?)',
    [title, content, owner],
    function (err) {
      if (err) {
        return res.status(500).json({ error: 'Error interno del servidor' })
      }

      res.json({
        message: 'Nota creada',
        id: this.lastID
      })
    }
  )
})

// ——— GET /notes (rate limit + XSS fix) ———
app.get('/notes', limiter15, (req, res) => {
  db.all('SELECT * FROM notes', (err, rows) => {
    if (err) {
      console.error('Notes query error:', err.message)
      return res.status(500).json({ error: 'Error interno del servidor' })
    }

    let html = '<h1>Notas</h1>'

    rows.forEach(note => {
      const safeTitle = escapeHtml(note.title || '')
      const safeContent = escapeHtml(note.content || '')
      const safeOwner = escapeHtml(note.owner || '')
      html += `
        <div style="border:1px solid #000;padding:10px;margin:10px;">
          <h2>${safeTitle}</h2>
          <p>${safeContent}</p>
          <small>${safeOwner}</small>
        </div>
      `
    })

    res.send(html)
  })
})

// ——— GET /user/:id (SQL injection fix + rate limit) ———
app.get('/user/:id', limiter15, (req, res) => {
  const rawId = req.params.id
  const id = parseInt(rawId, 10)

  if (!Number.isFinite(id) || id < 0) {
    return res.status(400).json({ error: 'ID inválido' })
  }

  db.get(
    'SELECT id, username, role FROM users WHERE id = ?',
    [id],
    (err, row) => {
      if (err) {
        console.error('User query error:', err.message)
        return res.status(500).json({ error: 'Error interno del servidor' })
      }

      if (!row) {
        return res.status(404).json({ error: 'Usuario no encontrado' })
      }

      res.json(row)
    }
  )
})

// ——— GET /admin ———
app.get('/admin', (req, res) => {
  res.send(`
    <h1>Panel Admin</h1>
    <p>Bienvenido administrador</p>
  `)
})

// ——— Error handler global genérico ———
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.message)
  res.status(500).json({ error: 'Error interno del servidor' })
})

app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`)
})
