const express = require('express');
const cors = require('cors');
const radius = require('radius');
const dgram = require('dgram');

const app = express();
app.use(cors());
app.use(express.json());

// ==========================================
// CONFIGURAÇÃO (tudo via variáveis de ambiente do Render — nunca hardcoded)
// ==========================================
const RADIUS_HOST = process.env.RADIUS_HOST;
const RADIUS_SECRET = process.env.RADIUS_SECRET;
const RADIUS_PORT = Number(process.env.RADIUS_PORT || 1812);
const RADIUS_TIMEOUT_MS = Number(process.env.RADIUS_TIMEOUT_MS || 5000);

// O servidor RADIUS (ver print do RouterOS) só tem o serviço "login"
// habilitado para este cliente. Sem o atributo Service-Type=Login-User,
// alguns servidores RADIUS simplesmente ignoram o pedido (o que aparece
// pra gente como timeout, mesmo com usuário/senha certos).
const RADIUS_NAS_IP_ADDRESS = process.env.RADIUS_NAS_IP_ADDRESS; // ex: IP público de saída do Render, se for fixo
const RADIUS_NAS_IDENTIFIER = process.env.RADIUS_NAS_IDENTIFIER || 'radius-proxy';

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!RADIUS_HOST || !RADIUS_SECRET) {
  console.error('⚠️  RADIUS_HOST e/ou RADIUS_SECRET não configurados nas variáveis de ambiente.');
}
if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error('⚠️  SUPABASE_URL e/ou SUPABASE_SERVICE_ROLE_KEY não configurados nas variáveis de ambiente.');
}

// ==========================================
// AUTENTICAÇÃO RADIUS
// ==========================================
function autenticarRadius(username, password) {
  return new Promise((resolve) => {
    const client = dgram.createSocket('udp4');
    let respondeu = false;

    const finalizar = (resultado) => {
      if (respondeu) return;
      respondeu = true;
      clearTimeout(timer);
      try { client.close(); } catch (_) { /* já fechado, ignora */ }
      resolve(resultado);
    };

    // Sem isso, se o servidor RADIUS nunca responder a requisição HTTP fica pendurada para sempre.
    const timer = setTimeout(() => {
      finalizar({ success: false, reason: 'timeout' });
    }, RADIUS_TIMEOUT_MS);

    client.on('error', () => finalizar({ success: false, reason: 'socket-error' }));

    client.on('message', (msg) => {
      try {
        const response = radius.decode({ packet: msg, secret: RADIUS_SECRET });
        finalizar({ success: response.code === 'Access-Accept' });
      } catch (e) {
        finalizar({ success: false, reason: 'decode-error' });
      }
    });

    // Monta os atributos base e acrescenta a identificação do NAS.
    // - Service-Type 'Login-User' faz o pedido bater com o serviço "login"
    //   que está habilitado nesse servidor RADIUS (os outros, como ppp e
    //   hotspot, estão desmarcados e não valem pra esse client).
    // - NAS-Identifier ajuda o servidor a reconhecer quem está perguntando.
    // - NAS-IP-Address só é enviado se configurado via env, porque o Render
    //   (plano free) não tem IP de saída fixo — mandar um IP errado é pior
    //   do que não mandar nenhum.
    const attributes = [
      ['User-Name', username],
      ['User-Password', password],
      ['Service-Type', 'Login-User'],
      ['NAS-Identifier', RADIUS_NAS_IDENTIFIER]
    ];

    if (RADIUS_NAS_IP_ADDRESS) {
      attributes.push(['NAS-IP-Address', RADIUS_NAS_IP_ADDRESS]);
    }

    let packet;
    try {
      packet = radius.encode({
        code: 'Access-Request',
        secret: RADIUS_SECRET,
        attributes
      });
    } catch (e) {
      finalizar({ success: false, reason: 'encode-error' });
      return;
    }

    client.send(packet, 0, packet.length, RADIUS_PORT, RADIUS_HOST, (err) => {
      if (err) finalizar({ success: false, reason: 'send-error' });
    });
  });
}

// ==========================================
// ROTAS
// ==========================================

// Apenas valida usuário/senha no RADIUS, sem mexer no Supabase.
app.post('/auth', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ success: false, reason: 'missing-fields' });
  }

  const resultado = await autenticarRadius(username, password);
  res.json(resultado);
});

// Valida usuário/senha no RADIUS e, se aprovado, insere o firewall no
// Supabase usando a service role key (que nunca é exposta ao navegador).
app.post('/add-firewall', async (req, res) => {
  const { username, password, nome, ip } = req.body || {};

  if (!username || !password || !nome || !ip) {
    return res.status(400).json({ success: false, reason: 'missing-fields' });
  }

  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    return res.status(500).json({ success: false, reason: 'server-misconfigured' });
  }

  const auth = await autenticarRadius(username, password);
  if (!auth.success) {
    return res.status(401).json({ success: false, reason: auth.reason || 'radius-denied' });
  }

  try {
    const resposta = await fetch(`${SUPABASE_URL}/rest/v1/fortigates`, {
      method: 'POST',
      headers: {
        apikey: SUPABASE_SERVICE_ROLE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation'
      },
      body: JSON.stringify({ nome, ip })
    });

    if (!resposta.ok) {
      const detalhe = await resposta.text().catch(() => '');
      console.error('Erro ao inserir no Supabase:', detalhe);
      return res.status(500).json({ success: false, reason: 'supabase-error' });
    }

    const data = await resposta.json();
    return res.json({ success: true, item: data[0] });
  } catch (e) {
    console.error('Exceção ao inserir no Supabase:', e);
    return res.status(500).json({ success: false, reason: 'supabase-exception' });
  }
});

// Valida usuário/senha no RADIUS e, se aprovado, exclui o registro do
// Supabase pelo id, usando a service role key.
app.post('/delete-firewall', async (req, res) => {
  const { username, password, id } = req.body || {};

  const idNumero = Number(id);
  if (!username || !password || !id || Number.isNaN(idNumero)) {
    return res.status(400).json({ success: false, reason: 'missing-fields' });
  }

  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    return res.status(500).json({ success: false, reason: 'server-misconfigured' });
  }

  const auth = await autenticarRadius(username, password);
  if (!auth.success) {
    return res.status(401).json({ success: false, reason: auth.reason || 'radius-denied' });
  }

  try {
    const resposta = await fetch(
      `${SUPABASE_URL}/rest/v1/fortigates?id=eq.${encodeURIComponent(idNumero)}`,
      {
        method: 'DELETE',
        headers: {
          apikey: SUPABASE_SERVICE_ROLE_KEY,
          Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
          Prefer: 'return=representation'
        }
      }
    );

    if (!resposta.ok) {
      const detalhe = await resposta.text().catch(() => '');
      console.error('Erro ao excluir no Supabase:', detalhe);
      return res.status(500).json({ success: false, reason: 'supabase-error' });
    }

    const data = await resposta.json();
    if (!data || data.length === 0) {
      return res.status(404).json({ success: false, reason: 'not-found' });
    }

    return res.json({ success: true, item: data[0] });
  } catch (e) {
    console.error('Exceção ao excluir no Supabase:', e);
    return res.status(500).json({ success: false, reason: 'supabase-exception' });
  }
});

// Rota simples para checar se o serviço está no ar (útil para "acordar" o
// Render antes de usar, já que o plano free hiberna após inatividade).
app.get('/', (req, res) => res.send('radius-proxy no ar'));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`radius-proxy rodando na porta ${port}`));
