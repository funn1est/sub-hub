import type { APIRoute } from "astro"

const body = (sitemapURL: URL) => `User-agent: *
Allow: /

Sitemap: ${sitemapURL.href}
`

export const GET: APIRoute = ({ site }) => {
  const sitemapURL = new URL(
    `${import.meta.env.BASE_URL}sitemap-index.xml`,
    site,
  )
  return new Response(body(sitemapURL), {
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
    },
  })
}
