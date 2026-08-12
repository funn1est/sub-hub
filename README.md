# Sub Hub

Sub Hub is a work-in-progress subscription-conversion project. Its current
implementation is a runtime-independent Rust core that parses selected VLESS
and Shadowsocks share URIs into a typed, client-independent node model.

The repository is under active development. It does not yet provide a public
conversion API, remote subscription fetching, or complete target-client
configuration generation.

## Compatibility and provenance

Sub Hub is a Rust implementation based on public protocol specifications and
interoperability research. Related open-source projects may be consulted to
understand ecosystem behavior. References to another project do not imply
source-level derivation, drop-in compatibility, affiliation, or endorsement.

Relevant public references include:

- [`tindy2013/subconverter`](https://github.com/tindy2013/subconverter)
- [Shadowsocks SIP002 URI scheme](https://shadowsocks.org/doc/sip002.html)
- [Shadowsocks 2022 Edition](https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-1-shadowsocks-2022-edition.md)
- [VMessAEAD / VLESS share-link proposal](https://github.com/XTLS/Xray-core/discussions/716)

Any third-party dependencies or incorporated materials remain subject to their
respective licenses and notices.

## License

Sub Hub is licensed under the
[GNU Affero General Public License v3.0 or later](LICENSE).
