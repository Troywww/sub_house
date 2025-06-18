export function formatUrl(url) {
    if (!url) return url;
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        return 'https://' + url;
    }
    return url;
}

export function isSubscriptionPath(path) {
    const subscriptionTypes = ['/a', '/b', '/c'];
    return subscriptionTypes.some(type => path.endsWith(type));
}

export function generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        const r = Math.random() * 16 | 0;
        const v = c == 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

export function createResponse(data, options = {}) {
    const { status = 200, headers = {} } = options;
    return new Response(
        typeof data === 'string' ? data : JSON.stringify(data),
        {
            status,
            headers: {
                'Content-Type': data instanceof Uint8Array ? 'application/octet-stream' : 'application/json',
                'Access-Control-Allow-Origin': '*',
                ...headers
            }
        }
    );
} 