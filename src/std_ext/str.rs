// unicode whitespace
// ref: https://www.unicode.org/Public/UCD/latest/ucd/PropList.txt
//
// 0009..000D    ; White_Space # Cc   [5] <control-0009>..<control-000D>
// 0020          ; White_Space # Zs       SPACE
// 0085          ; White_Space # Cc       <control-0085>
// 00A0          ; White_Space # Zs       NO-BREAK SPACE
// 1680          ; White_Space # Zs       OGHAM SPACE MARK
// 2000..200A    ; White_Space # Zs  [11] EN QUAD..HAIR SPACE
// 2028          ; White_Space # Zl       LINE SEPARATOR
// 2029          ; White_Space # Zp       PARAGRAPH SEPARATOR
// 202F          ; White_Space # Zs       NARROW NO-BREAK SPACE
// 205F          ; White_Space # Zs       MEDIUM MATHEMATICAL SPACE
// 3000          ; White_Space # Zs       IDEOGRAPHIC SPACE

// ascii whitespace
// ref: https://infra.spec.whatwg.org/#ascii-whitespace
//
// ASCII whitespace is U+0009 TAB, U+000A LF, U+000C FF, U+000D CR, or U+0020 SPACE.

pub const ASCII_WHITESPACE: [u8; 5] = [0x9, 0xa, 0xC, 0xd, 0x20];
