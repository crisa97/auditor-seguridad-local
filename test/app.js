const express = require('express')
const sqlite3 = require('sqlite3').verbose()
const bodyParser = require('body-parser')
const jwt = require('jsonwebtoken')

const app = express()
const PORT = 3000

app.use(bodyParser.urlencoded({ extended: true }))
app.use(bodyParser.json())


const db = new sqlite3.Database('./database.db')

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

  db.run(`
    INSERT INTO users(username, password, role)
    VALUES ('admin', 'admin123', 'admin')
  `)
})

app.post('/login', (req, res) => {
  const { username, password } = req.body

  const query = `
    SELECT * FROM users
    WHERE username = '${username}'
    AND password = '${password}'
  `

  console.log(query)

  db.get(query, (err, user) => {
    if (err) {
      return res.send(err.message)
    }

    if (!user) {
      return res.status(401).send('Credenciales inválidas')
    }

    const token = jwt.sign(
      {
        username: user.username,
        role: user.role
      },
      'secret123'
    )

    res.json({
      message: 'Login exitoso',
      token
    })
  })
})


app.post('/notes', (req, res) => {
  const { title, content, owner } = req.body

  db.run(
    `
      INSERT INTO notes(title, content, owner)
      VALUES (?, ?, ?)
    `,
    [title, content, owner],
    function (err) {
      if (err) {
        return res.send(err.message)
      }

      res.json({
        message: 'Nota creada',
        id: this.lastID
      })
    }
  )
})

app.get('/notes', (req, res) => {
  db.all('SELECT * FROM notes', (err, rows) => {
    if (err) {
      return res.send(err.message)
    }

    let html = '<h1>Notas</h1>'

    rows.forEach(note => {
      html += `
        <div style="border:1px solid #000;padding:10px;margin:10px;">
          <h2>${note.title}</h2>
          <p>${note.content}</p>
          <small>${note.owner}</small>
        </div>
      `
    })

    res.send(html)
  })
})


app.get('/user/:id', (req, res) => {
  const id = req.params.id

  db.get(
    `SELECT id, username, role FROM users WHERE id = ${id}`,
    (err, row) => {
      if (err) {
        return res.send(err.message)
      }

      res.json(row)
    }
  )
})


app.get('/admin', (req, res) => {
  res.send(`
    <h1>Panel Admin</h1>
    <p>Bienvenido administrador</p>
  `)
})


app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`)
})