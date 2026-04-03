/** @type {import('next').NextConfig} */
const backendApiBase = (process.env.BACKEND_API_BASE || 'http://127.0.0.1:8000').replace(/\/$/, '');

const nextConfig = {
    async rewrites() {
        return [
            {
                source: '/api/:path*',
                destination: `${backendApiBase}/api/:path*`,
            },
        ];
    },
};

module.exports = nextConfig;
