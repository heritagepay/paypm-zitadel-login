# DM Sans native assets

Strictly sans-serif UI family, bundled with the application. These static TTFs
were derived from `@fontsource-variable/dm-sans@5.3.0` normal `wght` Latin and
Latin Extended WOFF2 sources. Both subsets are merged; 400, 500, 600 and 700
are real instances, not synthetic bold. The upstream SIL Open Font License
is included in OFL.txt. No runtime font request is required.

Reproduce with FontTools: decode each subset, instantiate its `wght` axis at
the required weight, then merge the two static fonts using `fontTools.merge.Merger`.
Preserve the upstream font names and OFL when updating. Check French accents,
full business names and tabular amounts in the native capture suite.

Workforce enrollment uses these same real400/500/600 faces through route-scoped next/font/local. Canonical source: heritagepay/paypm-merchant-mobile commit71626ed6b5c19101b336d64d98efac7615ccb849, assets/fonts/DMSans. The global upstream Login Lato family is unchanged. SIL OFL is retained.
