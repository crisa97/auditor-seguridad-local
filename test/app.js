const express = require('express');
const multer = require('multer');
const fs = require('fs');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const upload = multer({
  dest: 'uploads/'
});

const users = [
  {
    id: 1,
    username: 'admin',
    password: '123456'
  }
];

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  const user = users.find(
    u => u.username == username && u.password == password
  );

  if (!user) {
    return res.status(401).json({
      message: 'Login failed'
    });
  }

  res.json({
    message: 'Login successful',
    user
  });
});

app.post('/upload', upload.single('file'), (req, res) => {
  res.json({
    filename: req.file.originalname,
    path: req.file.path
  });
});

app.get('/download', (req, res) => {
  const file = req.query.file;

  const content = fs.readFileSync(
    './documents/' + file,
    'utf8'
  );

  res.send(content);
});

app.post('/search', (req, res) => {
  const keyword = req.body.keyword;

  const html = `
    <html>
      <body>
        <h2>Resultados para: ${keyword}</h2>
      </body>
    </html>
  `;

  res.send(html);
});

app.listen(3000, () => {
  console.log('Server started');
});