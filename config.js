export const CONFIG = {
    // KV 存储配置
    KV_NAMESPACE: 'NODE_STORE',
    KV_KEY: 'nodes',
    COLLECTIONS_KEY: 'collections',

    // 外部服务配置
    SUB_WORKER_URL: '',
    SUBSCRIBER_URL: '',
    QUICK_SUB_URL: '',
    DEFAULT_TEMPLATE_URL: 'https://raw.githubusercontent.com/Troywww/singbox_conf/main/singbox_clash_conf.txt',

    // 认证配置
    DEFAULT_USERNAME: 'admin',
    DEFAULT_PASSWORD: 'admin',

    // 订阅相关配置
    SUBSCRIPTION: {
        BASE_PATH: '/a',
        SINGBOX_PATH: '/b',
        CLASH_PATH: '/c'
    },

    // API路径配置
    API: {
        NODES: '/api/nodes',
        COLLECTIONS: '/api/collections',
        SHARE: '/api/share',
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
            servers: [
                {
                    tag: "dns_proxy",
                    address: "tls://1.1.1.1",
                    address_resolver: "dns_resolver"
                },
                {
                    tag: "dns_direct",
                    address: "h3://dns.alidns.com/dns-query",
                    address_resolver: "dns_resolver",
                    detour: "direct",
                    strategy: "ipv4_only"
                },
                {
                    tag: "dns_fakeip",
                    address: "fakeip"
                },
                {
                    tag: "dns_resolver",
                    address: "223.5.5.5",
                    detour: "direct"
                },
                {
                    tag: "block",
                    address: "rcode://success"
                }
            ],
            rules: [
                {
                    outbound: ["any"],
                    server: "dns_resolver"
                },
                {
                    geosite: [
                        "category-ads-all"
                    ],
                    server: "dns_block",
                    disable_cache: true
                },
                {
                    geosite: [
                        "geolocation-!cn"
                    ],
                    query_type: [
                        "A",
                        "AAAA"
                    ],
                    server: "dns_fakeip"
                },
                {
                    geosite: [
                        "geolocation-!cn"
                    ],
                    server: "dns_proxy"
                },
                {
                    domain: [
                        "cloudflare.com",
                        "+.cloudflare.com",
                        "workers.dev",
                        "+.workers.dev"
                    ],
                    server: "dns_direct"
                }
            ],
            final: "dns_direct",
            independent_cache: true,
            fakeip: {
                enabled: true,
                inet4_range: "198.18.0.0/15"
            }
        },
        ntp: {
            enabled: true,
            server: "time.apple.com",
            server_port: 123,
            interval: "30m",
            detour: "direct"
        },
        inbounds: [
            {
                type: "mixed",
                tag: "mixed-in",
                listen: "0.0.0.0",
                listen_port: 2080
            },
            {
                type: "tun",
                tag: "tun-in",
                inet4_address: "172.19.0.1/30",
                auto_route: true,
                strict_route: true,
                stack: "mixed",
                sniff: true
            }
        ]
    },

    // Clash 基础配置
    CLASH_BASE_CONFIG: `port: 7890
socks-port: 7891
allow-lan: true
mode: rule
log-level: info
external-controller: :9090
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - 223.5.5.5
    - 119.29.29.29
  fallback:
    - 8.8.8.8
    - 8.8.4.4
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
