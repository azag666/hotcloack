const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const requestIp = require('request-ip');
const UAParser = require('ua-parser-js');
const axios = require('axios');

// INICIALIZAÇÃO
const app = express();
app.use(cors());
app.use(express.json());
app.use(requestIp.mw());

// --- CONFIGURAÇÃO DE AMBIENTE ---
// Pegando as chaves das Variáveis de Ambiente da Vercel
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY; 
const proxyKey = process.env.PROXY_KEY; // Opcional: Chave do proxycheck.io

// Conexão com o Banco de Dados
const supabase = createClient(supabaseUrl, supabaseKey);

// --- FUNÇÃO DE INTELIGÊNCIA MILITAR (O CÉREBRO) ---
async function checkRisk(ip, userAgent, referrer, settings) {
    const parser = new UAParser(userAgent);
    const os = parser.getOS();
    const device = parser.getDevice();
    const browser = parser.getBrowser();
    const uaUpper = userAgent.toUpperCase();

    // 1. FILTRO DE BOTS BÁSICOS (User Agent)
    const botTerms = ['FACEBOOK', 'GOOGLE', 'TWITTER', 'BOT', 'CRAWL', 'SPIDER', 'HEADLESS', 'LIGHTHOUSE', 'PTST', 'SELENIUM', 'PYTHON', 'CURL'];
    if (botTerms.some(term => uaUpper.includes(term))) {
        return { isBot: true, reason: `Bot Detectado (UA: ${browser.name || 'Unknown'})` };
    }

    // 2. FILTRO DE DESKTOP (Se a campanha for Mobile Only)
    if (!settings.allow_desktop) {
        // Bloqueia Windows, Mac OS e Linux (Desktop)
        const desktopOS = ['Windows', 'Mac OS', 'Ubuntu', 'Linux'];
        if (desktopOS.includes(os.name) && device.type !== 'mobile' && device.type !== 'tablet') {
             return { isBot: true, reason: 'Bloqueio de Desktop (Apenas Celular Permitido)' };
        }
    }

    // 3. FILTRO DE REFERRER (Se a campanha exigir origem Social)
    if (settings.require_referrer) {
        const socialSources = ['facebook', 'instagram', 'tiktok', 'youtube', 't.co']; // t.co = twitter
        const ref = (referrer || '').toLowerCase();
        
        // Se não tiver referrer ou se o referrer não contiver nenhuma das redes sociais
        const isSocial = socialSources.some(source => ref.includes(source));
        
        if (!ref || !isSocial) {
            return { isBot: true, reason: 'Acesso Direto/Desconhecido (Exigido Social)' };
        }
    }

    // 4. FILTRO DE IP / VPN / DATACENTER (Nível Avançado)
    // Só executa se tivermos uma chave de API configurada e a configuração da campanha pedir
    if (proxyKey) {
        try {
            // Verifica API externa (proxycheck.io é um exemplo popular e barato/grátis)
            const riskCheck = await axios.get(`http://proxycheck.io/v2/${ip}?key=${proxyKey}&vpn=1&asn=1`);
            const data = riskCheck.data[ip];
            
            if (data) {
                // Bloqueia VPN/Proxy se a campanha não permitir
                if (!settings.allow_vpn && data.proxy === "yes") {
                    return { isBot: true, reason: `VPN/Proxy Detectado (${data.provider || 'Unk'})` };
                }
                
                // Bloqueia Datacenters (Facebook/Google/AWS sempre usam isso)
                if (data.type === "Hosting" || data.type === "Business") {
                     return { isBot: true, reason: `IP de Servidor/Datacenter (${data.operator})` };
                }

                // Bloqueia País (Geolocalização)
                if (settings.country_allowed && settings.country_allowed !== 'ALL') {
                    if (data.iso !== settings.country_allowed) {
                        return { isBot: true, reason: `Geolocalização Errada (${data.iso})` };
                    }
                }
            }
        } catch (e) {
            console.error("Erro na verificação de IP (API externa):", e.message);
            // Em caso de falha da API, geralmente deixamos passar para não perder venda (Fail Open)
            // Ou bloqueamos se quisermos segurança máxima. Aqui vou deixar passar.
        }
    }

    return { isBot: false, reason: 'Tráfego Limpo' };
}

// --- ROTAS DA API ---

// 1. CLOAKING CHECK (Chamado pela Presell/Index.php)
app.post('/api/cloak', async (req, res) => {
    try {
        const { slug, user_agent, referrer, screen_width } = req.body;
        // Na Vercel/Proxy, o IP real vem no header x-forwarded-for
        const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.clientIp || '127.0.0.1'; 

        // Busca configurações da campanha
        const { data: campaign, error } = await supabase
            .from('campaigns')
            .select('*')
            .eq('slug', slug)
            .single();

        // Se não achar campanha ou erro, manda para o Google (Fallback seguro)
        if (error || !campaign) {
            return res.json({ action: 'safe', target: 'https://google.com' });
        }

        // Se campanha pausada -> Safe Page
        if (campaign.status !== 'active') {
             return res.json({ action: 'safe', target: campaign.safe_page });
        }

        // JS Challenge Básico (Bots simples não enviam screen_width ou enviam 0)
        if (!screen_width || screen_width < 100) {
            await supabase.from('hits').insert({ campaign_slug: slug, ip, is_bot: true, reason: 'Sem Resolução de Tela (Bot Simples)' });
            return res.json({ action: 'safe', target: campaign.safe_page });
        }

        // --- EXECUTA A ANÁLISE MILITAR ---
        const risk = await checkRisk(ip, user_agent, referrer, campaign);

        // Salva o Log no Supabase
        // Nota: O insert é assíncrono, não usamos await aqui para responder mais rápido ao usuário
        supabase.from('hits').insert({
            campaign_slug: slug,
            ip: ip, 
            device: user_agent.substring(0, 50), // Corta string longa
            is_bot: risk.isBot,
            reason: risk.reason
        }).then(() => {}); // Fire and forget

        // DECISÃO FINAL
        if (risk.isBot) {
            return res.json({ action: 'safe', target: campaign.safe_page });
        } else {
            return res.json({ action: 'money', target: campaign.money_page });
        }

    } catch (err) {
        console.error("Erro Fatal no Server:", err);
        // Em caso de pânico, sempre Safe Page
        return res.json({ action: 'safe', target: 'https://google.com' }); 
    }
});

// 2. CRIAR CAMPANHA (Chamado pelo Dashboard)
app.post('/api/campaigns', async (req, res) => {
    try {
        const { 
            slug, name, safe_page, money_page, country_allowed,
            allow_vpn, allow_desktop, require_referrer, pixel_id 
        } = req.body;

        // Validação
        if (!slug || !money_page || !safe_page) {
            return res.status(400).json({ error: 'Campos obrigatórios faltando.' });
        }

        const { data, error } = await supabase
            .from('campaigns')
            .insert([{ 
                slug, name, safe_page, money_page, country_allowed,
                allow_vpn, allow_desktop, require_referrer, pixel_id,
                status: 'active'
            }]);
        
        if(error) throw error;
        res.json({ success: true });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 3. ESTATÍSTICAS (Chamado pelo Dashboard)
app.get('/api/stats', async (req, res) => {
    try {
        // Busca Campanhas
        const { data: campaigns } = await supabase
            .from('campaigns')
            .select('*')
            .order('created_at', { ascending: false });

        // Busca últimos 200 hits (logs) para o gráfico "Matrix"
        const { data: hits } = await supabase
            .from('hits')
            .select('is_bot, campaign_slug, reason, ip, created_at')
            .order('created_at', { ascending: false })
            .limit(200);
        
        res.json({ campaigns, hits });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Porta padrão ou 3000
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`GhostCloak Elite rodando na porta ${PORT}`);
});

// Export necessário para Vercel Serverless Functions
module.exports = app;
