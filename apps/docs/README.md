# Sub Hub docs

Static product intro. It describes the current public Conversion Service
and Web Console surface. It is not a Conversion Service, not the Web
Console, and not a public instance.

This package lives at `apps/docs`. Node 24.19.0 and pnpm 11.22.0 are
pinned in the repository-root `mise.toml`. English is `/`. Chinese is
`/zh-cn/`. Copy tracks the README pair; product terms stay English in
the Chinese file. Do not put a published site URL in the README pair.

## Develop

```sh
pnpm install --frozen-lockfile
pnpm run dev
```

```sh
pnpm run build
pnpm run preview
```

CI builds this package. It does not publish the site. Do not put this
tree in `SUB_HUB_CONSOLE_ROOT` or the Worker `all` layout.
