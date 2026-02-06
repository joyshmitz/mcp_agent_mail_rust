//! Integration-test helpers for console output normalization.
//!
//! These helpers are intentionally conservative: strip common ANSI CSI sequences
//! (colors, cursor movement, clear) and OSC sequences (including OSC-8 links)
//! while preserving the human-visible text so tests can assert on stable
//! keywords/headers.

/// Strip ANSI escape codes (CSI) and OSC sequences from a string.
///
/// - CSI: `ESC [` ... final byte (`@`..`~`)
/// - OSC: `ESC ]` ... terminated by BEL (`\x07`) or ST (`ESC \\`)
#[must_use]
pub fn strip_ansi_and_osc(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\x1b' {
            match chars.peek().copied() {
                Some('[') => {
                    // CSI: ESC [ ... <final>
                    let _ = chars.next(); // '['
                    for ch in chars.by_ref() {
                        let cu = ch as u32;
                        if (0x40..=0x7E).contains(&cu) {
                            break;
                        }
                    }
                    continue;
                }
                Some(']') => {
                    // OSC: ESC ] ... BEL or ST (ESC \)
                    let _ = chars.next(); // ']'
                    loop {
                        match chars.next() {
                            None | Some('\x07') => break, // BEL
                            Some('\x1b') => {
                                if chars.peek().copied() == Some('\\') {
                                    let _ = chars.next(); // '\'
                                    break;
                                }
                            }
                            Some(_) => {}
                        }
                    }
                    continue;
                }
                Some(_) => {
                    // Drop one-character escapes (e.g. ESC c).
                    let _ = chars.next();
                    continue;
                }
                None => continue,
            }
        }

        // Normalize common control chars; preserve newline/tab for readability.
        if c == '\r' {
            continue;
        }
        if c.is_control() && c != '\n' && c != '\t' {
            continue;
        }

        out.push(c);
    }

    out
}

/// Strip ANSI/OSC and trim trailing whitespace on every line.
#[must_use]
pub fn normalize_console_text(input: &str) -> String {
    let stripped = strip_ansi_and_osc(input);
    stripped
        .lines()
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_sgr_sequences() {
        let s = "\u{1b}[1;32mhello\u{1b}[0m";
        assert_eq!(strip_ansi_and_osc(s), "hello");
    }

    #[test]
    fn strips_csi_clear_and_cursor_moves() {
        let s = "a\u{1b}[2Jb\u{1b}[Hc";
        assert_eq!(strip_ansi_and_osc(s), "abc");
    }

    #[test]
    fn strips_osc8_hyperlinks_bel_terminated() {
        let s = "\u{1b}]8;;https://example.com\u{7}link\u{1b}]8;;\u{7}";
        assert_eq!(strip_ansi_and_osc(s), "link");
    }

    #[test]
    fn strips_osc8_hyperlinks_st_terminated() {
        let s = "\u{1b}]8;;https://example.com\u{1b}\\link\u{1b}]8;;\u{1b}\\";
        assert_eq!(strip_ansi_and_osc(s), "link");
    }

    #[test]
    fn normalize_trims_trailing_spaces_per_line() {
        let s = "a  \n b\t \n";
        assert_eq!(normalize_console_text(s), "a\n b");
    }
}
