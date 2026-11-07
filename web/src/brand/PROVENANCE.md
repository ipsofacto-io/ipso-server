# Provenance of the brand kit

The files of this directory are a copy of `src/` of the private repository `ipsofacto-io/ipso-brand-kit`, without `styles/fonts.css`, at commit `7fff44c5397033a89be6eba68b512f0378c4ee16`. `web/public` holds the favicon, the app icons and the manifest of the kit's `public/` at the same commit.

Do not edit these files here. A change of the identity is a pull request in the kit first, and then this copy is repeated at the new commit and this file names it ([ADR-0107](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0107-brand-kit-visual-system.md)).

The kit is private and this repository is public, so the app copies what it needs and does not fetch the kit at build time.

## Copy it

From the root of this repository, with the kit checked out at the commit to take:

```sh
KIT=../ipso-brand-kit
find web/src/brand -mindepth 1 ! -name PROVENANCE.md -delete
cp -R "$KIT/src/." web/src/brand/
rm web/src/brand/styles/fonts.css
for f in favicon.ico favicon.svg apple-touch-icon.png icon-192.png icon-512.png icon-maskable-512.png site.webmanifest; do
  cp "$KIT/public/$f" "web/public/$f"
done
```

`styles/fonts.css` is left out because it imports the fonts from Google Fonts, and the content security policy of the app allows no other origin. The same two families are served from the app by `@fontsource` (`web/src/fonts.ts`). `components/brand-geometry.ts` and `tokens/tokens.ts` are generated in the kit and are never edited by hand.
