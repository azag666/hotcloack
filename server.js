// server.js (ou api/index.js na Vercel)
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const requestIp = require('request-ip');
const UAParser = require('ua-parser-js');
const axios = require('axios');

// CONFIGURAÇÃO
const app = express();
app.use(cors());
app.use(express.json());
app.use(requestIp.mw());

// CONEXÃO COM SUPABASE (Coloque suas chaves reais aqui ou em .env)
const supabaseUrl = 'SUA_URL_DO_SUPABASE';
const supabaseKey = 'SUA_KEY_DO_SUPABASE';
const supabase = createClient(supabaseUrl, supabaseKey);

// API DE VERIFICAÇÃO DE PROXY (Crie conta grátis no proxycheck.io ou similar)
// Se não tiver chave, a verificação de VPN será limitada.
const PROXY_KEY = 'SUA_API_KEY_PROXYCHECK_IO'; 

// --- FUNÇÃO DE INTELIGÊNCIA MILITAR ---
async function checkRisk(ip, userAgent, settings) {
    let reason = null;
    let isBot = false;

    // 1. ANÁLISE DE USER AGENT (Nível 1)
    const parser = new UAParser(userAgent);
    const browser = parser.getBrowser();
    const os = parser.getOS();
    const uaUpper = userAgent.toUpperCase();

    const botTerms = ['FACEBOOK', 'GOOGLE', 'TWITTER', 'BOT', 'CRAWL', 'HEADLESS', 'LIGHTHOUSE', 'PTST', 'SELENIUM'];
    if (botTerms.some(term => uaUpper.includes(term))) {
        return { isBot: true, reason: `Bot Detectado (UA: ${term})` };
    }

    // 2. DISPOSITIVO (Nível 2)
    if (!settings.allow_desktop && (os.name === 'Windows' || os.name === 'Mac OS')) {
         return { isBot: true, reason: 'Bloqueio de Desktop (Apenas Mobile)' };
    }

    // 3. CONSULTA EXTERNA DE IP (Nível 3 - O mais importante)
    // Verifica se é VPN, Proxy ou Datacenter (AWS, Azure, Facebook Servers)
    try {
        if (PROXY_KEY) {
            const riskCheck = await axios.get(`http://proxycheck.io/v2/${ip}?key=${PROXY_KEY}&vpn=1&asn=1`);
            const data = riskCheck.data[ip];
            
            if (data) {
                // Bloqueia se for Proxy/VPN (a menos que permitido)
                if (data.proxy === "yes" && !settings.allow_vpn) {
                    return { isBot: true, reason: `VPN/Proxy Detectado (${data.provider || 'Unk'})` };
                }
                
                // Bloqueia Datacenters (Facebook/Google hospedagem)
                if (data.type === "Hosting" || data.type === "Business") {
                     return { isBot: true, reason: `IP de Datacenter/Servidor (${data.operator})` };
                }

                // Bloqueia País incorreto
                if (settings.country_allowed && data.iso !== settings.country_allowed) {
                    return { isBot: true, reason: `Geolocalização Errada (${data.iso})` };
                }
            }
        }
    } catch (e) {
        console.error("Erro na API de IP:", e.message);
        // Em caso de erro na API, por segurança, podemos deixar passar ou bloquear.
        // Vamos logar mas deixar passar para não perder vendas reais por erro de API.
    }

    return { isBot: false, reason: 'Tráfego Limpo' };
}

// --- ROTAS ---

// ROTA 1: O Check Principal
app.post('/api/cloak', async (req, res) => {
    const { slug, user_agent, referrer, screen_width } = req.body;
    // Na Vercel, o IP real vem no header x-forwarded-for
    const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.clientIp; 

    // Busca configurações da campanha
    const { data: campaign, error } = await supabase
        .from('campaigns')
        .select('*')
        .eq('slug', slug)
        .single();

    if (error || !campaign) {
        return res.json({ action: 'safe', target: 'https://google.com' }); // Fallback
    }

    if (campaign.status !== 'active') {
         return res.json({ action: 'safe', target: campaign.safe_page });
    }

    // JS Challenge (Verifica se o navegador enviou resolução de tela - Bots burros não enviam)
    if (!screen_width || screen_width < 100) {
        await supabase.from('hits').insert({ campaign_slug: slug, ip, is_bot: true, reason: 'Sem Resolução de Tela (Bot Simples)' });
        return res.json({ action: 'safe', target: campaign.safe_page });
    }

    // Executa a Análise Militar
    const risk = await checkRisk(ip, user_agent, campaign);

    // Salva o Log
    await supabase.from('hits').insert({
        campaign_slug: slug,
        ip: ip, // Em produção, faça hash do IP para privacidade se necessário
        country: 'XX', // Preencher com dados da API de IP
        device: user_agent.substring(0, 50),
        is_bot: risk.isBot,
        reason: risk.reason
    });

    if (risk.isBot) {
        return res.json({ action: 'safe', target: campaign.safe_page });
    } else {
        return res.json({ action: 'money', target: campaign.money_page });
    }
});

// ROTA 2: Criar Campanha
app.post('/api/campaigns', async (req, res) => {
    const { slug, name, safe_page, money_page, country_allowed } = req.body;
    const { data, error } = await supabase
        .from('campaigns')
        .insert([{ slug, name, safe_page, money_page, country_allowed }]);
    
    if(error) return res.status(500).json(error);
    res.json({ success: true });
});

// ROTA 3: Dashboard Stats
app.get('/api/stats', async (req, res) => {
    // Retorna campanhas e contagem simples
    const { data: campaigns } = await supabase.from('campaigns').select('*');
    const { data: hits } = await supabase.from('hits').select('is_bot, campaign_slug').order('created_at', { ascending: false }).limit(500);
    
    res.json({ campaigns, hits });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`GhostCloak Elite rodando na porta ${PORT}`));
