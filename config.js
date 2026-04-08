export const CONFIG = {
    // KV 存储配置
    KV_NAMESPACE: 'NODE_STORE',
    KV_KEY: 'nodes',
    COLLECTIONS_KEY: 'collections',
    APP_SETTINGS_KEY: 'app_settings',

    // 外部服务配置
    SUB_WORKER_URL: '',
    SUBSCRIBER_URL: '',
    QUICK_SUB_URL: '',
    DEFAULT_TEMPLATE_URL: 'https://raw.githubusercontent.com/Troywww/singbox_conf/main/singbox_clash_conf.txt',

    // 认证配置
    DEFAULT_USERNAME: '',
    DEFAULT_PASSWORD: '',

    // 订阅相关配置
    SUBSCRIPTION: {
        BASE_PATH: '/base',
        SINGBOX_PATH: '/singbox',
        CLASH_PATH: '/clash'
    },

    // API路径配置
    API: {
        NODES: '/api/nodes',
        COLLECTIONS: '/api/collections',
        TEMPLATES: '/api/templates',
        RULES: '/api/rules',
        RULES_PRESETS: '/api/rules/presets',
        SETTINGS: '/api/settings',
        SHARE: '/api/share',
        ADMIN: {
            BASE: '/api/admin',
            LOGIN: '/api/admin/login',
            SESSION: '/api/admin/session',
            LOGOUT: '/api/admin/logout'
        },
        USER: {
            BASE: '/api/user',
            LOGIN: '/api/user/login',
            PAGE: '/user',
            LOGOUT: '/api/user/logout'
        }
    },

    // 用户访问配置
    USER_TOKENS_KEY: 'user_tokens',  // 存储用户令牌的KV key
    USER_SESSION_KEY: 'user_sessions',
    USER_SESSION_EXPIRE: 86400, // 24小时

    // SingBox 基础配置
    SINGBOX_BASE_CONFIG: {
        log: {
            disabled: false,
            level: "info",
            timestamp: true
        },
        dns: {
            strategy: "prefer_ipv4",
            independent_cache: true,
            servers: [
                {
                    type: "https",
                    tag: "dns-remote",
                    server: "1.1.1.1",
                    server_port: 443,
                    path: "/dns-query",
                    detour: "select"
                },
                {
                    type: "https",
                    tag: "dns-direct",
                    server: "223.5.5.5",
                    server_port: 443,
                    path: "/dns-query"
                }
            ],
            rules: [
                {
                    clash_mode: "Direct",
                    action: "route",
                    server: "dns-direct"
                },
                {
                    clash_mode: "Global",
                    action: "route",
                    server: "dns-remote"
                },
                {
                    query_type: ["HTTPS"],
                    action: "route",
                    server: "dns-remote"
                }
            ]
        },
        inbounds: [
            {
                type: "mixed",
                tag: "mixed-in",
                listen: "0.0.0.0",
                listen_port: 2080
            }
        ],
        ntp: {
            enabled: true,
            server: "time.apple.com",
            server_port: 123,
            interval: "30m"
        },
        route: {
            rules: [
                {
                    inbound: ["mixed-in"],
                    action: "sniff"
                }
            ],
            auto_detect_interface: true,
            default_domain_resolver: {
                server: "dns-direct",
                strategy: "prefer_ipv4"
            }
        }
    },

    // Clash 基础配置
    CLASH_BASE_CONFIG: `mixed-port: 7890
redir-port: 7892
tproxy-port: 7893
allow-lan: true
mode: rule
log-level: info
ipv6: false
tcp-concurrent: true
unified-delay: true
find-process-mode: strict
global-client-fingerprint: chrome
external-controller: 127.0.0.1:9090
dns:
  enable: true
  cache-algorithm: arc
  ipv6: false
  prefer-h3: false
  respect-rules: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter-mode: blacklist
  nameserver:
    - https://223.5.5.5/dns-query
    - https://1.1.1.1/dns-query
  proxy-server-nameserver:
    - https://1.1.1.1/dns-query
  direct-nameserver:
    - 223.5.5.5
    - 119.29.29.29
  fallback:
    - https://8.8.8.8/dns-query
    - https://1.0.0.1/dns-query
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
  fake-ip-filter:
    - '*.lan'
    - localhost.ptlogin2.qq.com
    - '+.srv.nintendo.net'
    - '+.stun.playstation.net'
    - '+.msftconnecttest.com'
    - '+.msftncsi.com'
    - '+.xboxlive.com'
    - 'msftconnecttest.com'
    - 'xbox.*.microsoft.com'
    - '*.battlenet.com.cn'
    - '*.battlenet.com'
    - '*.blzstatic.cn'
    - '*.battle.net'`,

    COOKIE: {
        SESSION_NAME: 'session',
        ADMIN_SESSION_NAME: 'admin_session',
        MAX_AGE: 86400  // 24小时
    },

    // 用户会话配置
    USER: {
        BASE: '/api/user',
        LOGIN: '/api/user/login',
        PAGE: '/user',
        SECRET: '/user/secret'
    },

    // 会话过期时间（24小时）
    SESSION_TTL: 24 * 60 * 60,

    // KV key 前缀
    KV_PREFIX: {
        SESSION: 'session:'  // 会话数据前缀
    }
};

export const RULE_PRESETS = [
    {
        id: 'ads',
        name: '广告拦截',
        clash: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/ads.mrs',
            format: 'mrs'
        },
        singbox: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/sing-box-ruleset/ads.srs',
            format: 'binary'
        }
    },
    {
        id: 'private',
        name: '私有网络',
        clash: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/private.mrs',
            format: 'mrs'
        },
        singbox: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/sing-box-ruleset/private.srs',
            format: 'binary'
        }
    },
    {
        id: 'applications',
        name: '常见应用',
        clash: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/applications.list',
            format: 'text'
        },
        singbox: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/sing-box-ruleset/applications.srs',
            format: 'binary'
        }
    },
    {
        id: 'apple',
        name: '苹果服务',
        clash: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/apple-cn.mrs',
            format: 'mrs'
        },
        singbox: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/sing-box-ruleset/apple-cn.srs',
            format: 'binary'
        }
    },
    {
        id: 'google',
        name: '谷歌服务',
        clash: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/google-cn.mrs',
            format: 'mrs'
        },
        singbox: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/sing-box-ruleset/google-cn.srs',
            format: 'binary'
        }
    },
    {
        id: 'microsoft',
        name: '微软服务',
        clash: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/microsoft-cn.mrs',
            format: 'mrs'
        },
        singbox: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/sing-box-ruleset/microsoft-cn.srs',
            format: 'binary'
        }
    },
    {
        id: 'ai',
        name: 'AI 平台',
        clash: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/ai.mrs',
            format: 'mrs'
        },
        singbox: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/sing-box-ruleset/ai.srs',
            format: 'binary'
        }
    },
    {
        id: 'games',
        name: '游戏平台',
        clash: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/games.mrs',
            format: 'mrs'
        },
        singbox: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/sing-box-ruleset/games.srs',
            format: 'binary'
        }
    },
    {
        id: 'games-cn',
        name: '游戏服务',
        clash: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/games-cn.mrs',
            format: 'mrs'
        },
        singbox: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/sing-box-ruleset/games-cn.srs',
            format: 'binary'
        }
    },
    {
        id: 'netflix',
        name: '奈飞视频',
        clash: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/netflix.mrs',
            format: 'mrs'
        },
        singbox: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/sing-box-ruleset/netflix.srs',
            format: 'binary'
        }
    },
    {
        id: 'disney',
        name: '迪士尼+',
        clash: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/disney.mrs',
            format: 'mrs'
        },
        singbox: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/sing-box-ruleset/disney.srs',
            format: 'binary'
        }
    },
    {
        id: 'max',
        name: 'Max',
        clash: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/max.mrs',
            format: 'mrs'
        },
        singbox: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/sing-box-ruleset/max.srs',
            format: 'binary'
        }
    },
    {
        id: 'primevideo',
        name: 'Prime Video',
        clash: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/primevideo.mrs',
            format: 'mrs'
        },
        singbox: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/sing-box-ruleset/primevideo.srs',
            format: 'binary'
        }
    },
    {
        id: 'appletv',
        name: 'Apple TV+',
        clash: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/appletv.mrs',
            format: 'mrs'
        },
        singbox: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/sing-box-ruleset/appletv.srs',
            format: 'binary'
        }
    },
    {
        id: 'youtube',
        name: '油管视频',
        clash: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/youtube.mrs',
            format: 'mrs'
        },
        singbox: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/sing-box-ruleset/youtube.srs',
            format: 'binary'
        }
    },
    {
        id: 'tiktok',
        name: 'TikTok',
        clash: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/tiktok.mrs',
            format: 'mrs'
        },
        singbox: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/sing-box-ruleset/tiktok.srs',
            format: 'binary'
        }
    },
    {
        id: 'bilibili',
        name: '哔哩哔哩',
        clash: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/bilibili.mrs',
            format: 'mrs'
        },
        singbox: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/sing-box-ruleset/bilibili.srs',
            format: 'binary'
        }
    },
    {
        id: 'spotify',
        name: 'Spotify',
        clash: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/spotify.mrs',
            format: 'mrs'
        },
        singbox: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/sing-box-ruleset/spotify.srs',
            format: 'binary'
        }
    },
    {
        id: 'media',
        name: '国外媒体',
        clash: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/media.mrs',
            format: 'mrs'
        },
        singbox: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/sing-box-ruleset/media.srs',
            format: 'binary'
        }
    },
    {
        id: 'networktest',
        name: '网络测试',
        clash: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/networktest.mrs',
            format: 'mrs'
        },
        singbox: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/sing-box-ruleset/networktest.srs',
            format: 'binary'
        }
    },
    {
        id: 'tld-proxy',
        name: '国外顶级域名',
        clash: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/tld-proxy.mrs',
            format: 'mrs'
        },
        singbox: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/sing-box-ruleset/tld-proxy.srs',
            format: 'binary'
        }
    },
    {
        id: 'gfw',
        name: 'GFW',
        clash: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/gfw.mrs',
            format: 'mrs'
        },
        singbox: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/sing-box-ruleset/gfw.srs',
            format: 'binary'
        }
    },
    {
        id: 'proxy',
        name: '国外域名',
        clash: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/proxy.mrs',
            format: 'mrs'
        },
        singbox: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/sing-box-ruleset/proxy.srs',
            format: 'binary'
        }
    },
    {
        id: 'cn',
        name: '国内域名',
        clash: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/cn.mrs',
            format: 'mrs'
        },
        singbox: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/sing-box-ruleset/cn.srs',
            format: 'binary'
        }
    },
    {
        id: 'privateip',
        name: '私有 IP',
        clash: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/privateip.mrs',
            format: 'mrs'
        },
        singbox: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/sing-box-ruleset/privateip.srs',
            format: 'binary'
        }
    },
    {
        id: 'cnip',
        name: '中国大陆 IP',
        clash: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/cnip.mrs',
            format: 'mrs'
        },
        singbox: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/sing-box-ruleset/cnip.srs',
            format: 'binary'
        }
    },
    {
        id: 'telegramip',
        name: 'Telegram IP',
        clash: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/telegramip.mrs',
            format: 'mrs'
        },
        singbox: {
            url: 'https://github.com/DustinWin/ruleset_geodata/releases/download/sing-box-ruleset/telegramip.srs',
            format: 'binary'
        }
    }
];

export const TEMPLATE_PRESETS = [
    {
        id: 'dustinwin-proxy-first',
        name: 'DustinWin 风格 - 代理优先',
        description: '白名单思路，国内和常见直连流量走直连，其余流量优先走节点选择。',
        content: [
            'custom_proxy_group=节点选择`select`[]DIRECT`.*',
            'custom_proxy_group=AI 服务`url-test`(ChatGPT|OpenAI|Perplexity|Grok|Claude|Gemini|Copilot|Cursor|POE)`[]节点选择',
            'custom_proxy_group=Telegram`url-test`(Telegram|TG)`[]节点选择',
            'custom_proxy_group=Apple 服务`select`[]DIRECT`[]节点选择',
            'custom_proxy_group=Google 服务`select`[]DIRECT`[]节点选择',
            'custom_proxy_group=微软服务`select`[]DIRECT`[]节点选择',
            'custom_proxy_group=游戏平台`select`[]节点选择`[]DIRECT',
            'custom_proxy_group=奈飞视频`url-test`(Netflix|NF|奈飞)`[]节点选择',
            'custom_proxy_group=油管视频`url-test`(YouTube|YT)`[]节点选择',
            'custom_proxy_group=TikTok`url-test`(TikTok)`[]节点选择',
            'custom_proxy_group=国外媒体`select`[]节点选择`[]DIRECT',
            'custom_proxy_group=广告拦截`select`[]REJECT`[]DIRECT',
            'custom_proxy_group=漏网之鱼`select`[]节点选择`[]DIRECT',
            '',
            'ruleset=广告拦截,@ads',
            'ruleset=DIRECT,@private',
            'ruleset=DIRECT,@applications',
            'ruleset=Apple 服务,@apple',
            'ruleset=Google 服务,@google',
            'ruleset=微软服务,@microsoft',
            'ruleset=游戏平台,@games',
            'ruleset=AI 服务,@ai',
            'ruleset=Telegram,@telegramip',
            'ruleset=奈飞视频,@netflix',
            'ruleset=油管视频,@youtube',
            'ruleset=TikTok,@tiktok',
            'ruleset=国外媒体,@media',
            'ruleset=节点选择,@proxy',
            'ruleset=节点选择,@gfw',
            'ruleset=节点选择,@tld-proxy',
            'ruleset=DIRECT,@cn',
            'ruleset=DIRECT,@privateip',
            'ruleset=DIRECT,@cnip',
            'ruleset=漏网之鱼,[]MATCH'
        ].join('\n')
    },
    {
        id: 'dustinwin-direct-first',
        name: 'DustinWin 风格 - 直连优先',
        description: '黑名单思路，仅命中特定规则的流量走代理，适合日常直连为主的场景。',
        content: [
            'custom_proxy_group=节点选择`select`[]DIRECT`.*',
            'custom_proxy_group=AI 服务`url-test`(ChatGPT|OpenAI|Perplexity|Grok|Claude|Gemini|Copilot|Cursor|POE)`[]节点选择',
            'custom_proxy_group=Telegram`url-test`(Telegram|TG)`[]节点选择',
            'custom_proxy_group=国外媒体`select`[]节点选择`[]DIRECT',
            'custom_proxy_group=广告拦截`select`[]REJECT`[]DIRECT',
            '',
            'ruleset=广告拦截,@ads',
            'ruleset=DIRECT,@private',
            'ruleset=DIRECT,@applications',
            'ruleset=AI 服务,@ai',
            'ruleset=Telegram,@telegramip',
            'ruleset=国外媒体,@media',
            'ruleset=节点选择,@tld-proxy',
            'ruleset=节点选择,@gfw',
            'ruleset=节点选择,@proxy',
            'ruleset=DIRECT,[]MATCH'
        ].join('\n')
    }
];

// 获取配置值，优先使用环境变量
export function getConfig(key, env = {}) {
    // 环境变量名称映射
    const envMap = {
        SUB_WORKER_URL: 'SUB_WORKER_URL',
        SUBSCRIBER_URL: 'SUBSCRIBER_URL',
        QUICK_SUB_URL: 'QUICK_SUB_URL',
        DEFAULT_TEMPLATE_URL: 'DEFAULT_TEMPLATE_URL'
    };

    // 如果存在对应的环境变量，优先使用环境变量的值
    if (envMap[key] && env[envMap[key]]) {
        return env[envMap[key]];
    }

    // 否则返回配置文件中的默认值
    return CONFIG[key];
}
