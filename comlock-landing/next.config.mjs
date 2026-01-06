/** @type {import('next').NextConfig} */
const nextConfig = {
    reactStrictMode: true,
    headers: async () => [
        {
            source: '/:path*',
            headers: [
                {
                    key: 'Content-Security-Policy',
                    value: "default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data: https://avatars.githubusercontent.com; connect-src 'self' https://api.github.com;",
                },
                {
                    key: 'X-Frame-Options',
                    value: 'DENY',
                },
                {
                    key: 'X-Content-Type-Options',
                    value: 'nosniff',
                },
                {
                    key: 'Referrer-Policy',
                    value: 'origin-when-cross-origin',
                },
            ],
        },
    ],
};

export default nextConfig;
