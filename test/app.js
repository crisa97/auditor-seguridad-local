const express = require('express');
const multer = require('multer');
const { exec } = require('child_process');
const fs = require('fs');
const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
const upload = multer({
  dest: 'uploads/'
});
app.post('/upload', upload.single('file'), (req, res) => {
  
  const username = req.body.username;
  const filename = req.file.originalname;
  exec`mv uploads/${req.file.filename} uploads/${filename}`, (err) => {
    if (err) {
      return res.send(err.message);
    }
    res.send(`
      <h1>Archivo subido</h1>
      <p>Usuario: ${username}</p>
      <p>Archivo: ${filename}</p>
    `);
  });
});
app.get('/read', (req, res) => {
  const file = req.query.file;
  fs.readFile`uploads/${file}`, 'utf8', (err, data) => {
    if (err) {
      return res.send('Error leyendo archivo');
    }
    res.send(data);
  });
});
app.listen(3000, () => {
  console.log('Servidor ejecutándose');
});