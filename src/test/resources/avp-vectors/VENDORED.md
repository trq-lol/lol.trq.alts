# AVP 0.5 conformance vectors (vendored)

Every file in this directory except this note and `0.4/` is a byte-for-byte copy of
`vectors/` in the Alt Vault Protocol spec repository, `trqlmao/avp`, at commit `3dbdf79`
(protocol 0.5). `README.md` is the upstream description of the vectors, also verbatim.
`generate.ts`, the upstream generator, is not vendored.

These files are the **source of truth**: never edit them here. The tests under
`lol.trq.alts.internal.avp` reproduce every positive case byte for byte and reject every
`negative.json` case, and `AvpVectorFilesTest` pins the SHA-256 of each file below, so a
local edit fails the build.

To update: copy each file from the new commit with `git show <commit>:vectors/<file>`
(never a working tree), replace the hashes below and in `AvpVectorFilesTest`, update the
commit named here, and update the tests if the shape of a vector changed. A changed case count
fails the tests until the expected counts are updated on purpose.

SHA-256 at `3dbdf79`:

```
c517b14251ebfc9ae994146398a503bbe771b7086699b0e1c98235a74b1639f0  acceptance.json
2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda  bip39-english.txt
cb94bb9ec771d5861cecaabeecd6e8103f7fe6c8791a7674d5fbcfafa13d3a14  bip39-owner.json
05dfe65f5f7c6db5ef1cf86cdf0c4730d31096c1ccdc5c335c4f685813ff8503  commit.json
6845ffe793a6323235e1a062fae5ac3ba6867cfd2b9e90ea4f79e2c68e86372e  ed25519.json
0d319d4e56b51b29ca0a56e606040b49be19c497663d10895a973835ab642dd7  federation.json
52f1cc2ef6b9586156671a71384306322b3298624fa134eee9f5b8e5dd764d74  hkdf.json
308d641590f93a5bb718eececb92e0cf5484b2b5e5b5814c73d7f23bb5948958  index.json
0b32246bb7067e93eca21283e0ebc8f1c3987ef4e6e8d5942cc55689f0d1bf4a  key-wrap.json
df9a531c4298441b8d88faa2917d917a01825a854d6f7281b1b49976f0b41ca8  manifest.json
f33bf3782f1bf3c69e190140ebbf16c3c1f1bd28b8fff0c2a24609a856531bf5  merge.json
0b09642301587a5db6ce13138976a94423761cd75f40b846dd193537feeefe79  negative.json
9b8fca1209dd8e24b8589b477ac0ac522c72faecc3d3139e603f762dad772f70  README.md
070ef12805fe4ac6d718ded40a210c1c829e1739d68b61e3ff529ca1e0257cbd  x25519.json
```
