const express = require('express');
const radius = require('radius');
const dgram = require('dgram');

const app = express();
app.use(express.json());

const RADIUS_HOST = '187.86.128.106';
const RADIUS_SECRET = 'vetorialteste';

app.post('/auth', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({success: false});

  // Pacote RADIUS simples
  const packet = radius.encode({
    code: 'Access-Request',
    secret: RADIUS_SECRET,
    attributes: [
      ['User-Name', username],
      ['User-Password', password]
    ]
  });

  const client = dgram.createSocket('udp4');
  client.send(packet, 0, packet.length, 1812, RADIUS_HOST, (err) => {
    if (err) return res.json({success: false});
  });

  client.on('message', (msg) => {
    const response = radius.decode({packet: msg, secret: RADIUS_SECRET});
    client.close();
    res.json({success: response.code === 'Access-Accept'});
  });
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Proxy rodando na porta ${port}`));
