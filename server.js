const express = require('express');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;

// Alle Routen liefern index.html aus (Single Page App)
app.use(express.static(path.join(__dirname)));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server läuft auf Port ${PORT}`);
});
