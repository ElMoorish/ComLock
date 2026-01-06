export interface ReleaseAsset {
    name: string;
    size: number;
    download_url: string;
}

export interface ReleaseData {
    tag_name: string;
    published_at: string;
    html_url: string;
    assets: {
        apk: ReleaseAsset | null;
        ipa: ReleaseAsset | null;
        web: ReleaseAsset | null;
    };
}

const REPO_OWNER = "ElMoorish";
const REPO_NAME = "ComLock";

export async function getLatestRelease(): Promise<ReleaseData | null> {
    try {
        const res = await fetch(
            `https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest`,
            {
                next: { revalidate: 3600 }, // Cache for 1 hour to Avoid Rate Limits
                headers: {
                    Accept: "application/vnd.github.v3+json",
                },
            }
        );

        if (!res.ok) {
            console.warn(`GitHub API Error: ${res.status} ${res.statusText}`);
            return null;
        }

        const data = await res.json();

        // Helper to find specific assets
        const findAsset = (ext: string) => {
            const asset = data.assets.find((a: any) => a.name.endsWith(ext));
            if (!asset) return null;
            return {
                name: asset.name,
                size: asset.size,
                download_url: asset.browser_download_url,
            };
        };

        return {
            tag_name: data.tag_name,
            published_at: data.published_at,
            html_url: data.html_url,
            assets: {
                apk: findAsset(".apk"),
                ipa: findAsset(".ipa"),
                web: findAsset(".zip"),
            },
        };
    } catch (error) {
        console.error("Failed to fetch release:", error);
        return null;
    }
}

export function formatBytes(bytes: number, decimals = 1) {
    if (!+bytes) return '0 B';

    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];

    const i = Math.floor(Math.log(bytes) / Math.log(k));

    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}
