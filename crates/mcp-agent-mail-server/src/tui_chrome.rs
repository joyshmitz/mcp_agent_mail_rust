//! Chrome shell for `AgentMailTUI`: tab bar, status line, help overlay.
//!
//! The chrome renders persistent UI elements that frame every screen.
//! Layout: `[tab_bar(1)] [screen_content(fill)] [status_line(1)]`

use ftui::layout::{Constraint, Flex, Rect};
use ftui::widgets::Widget;
use ftui::widgets::block::Block;
use ftui::widgets::borders::BorderType;
use ftui::widgets::paragraph::Paragraph;
use ftui::{Frame, PackedRgba, Style};

use crate::tui_bridge::TuiSharedState;
use crate::tui_screens::{HelpEntry, MAIL_SCREEN_REGISTRY, MailScreenId, screen_meta};

// ──────────────────────────────────────────────────────────────────────
// Color palette
// ──────────────────────────────────────────────────────────────────────

const TAB_ACTIVE_BG: PackedRgba = PackedRgba::rgb(50, 70, 110);
const TAB_INACTIVE_BG: PackedRgba = PackedRgba::rgb(30, 35, 50);
const TAB_ACTIVE_FG: PackedRgba = PackedRgba::rgb(255, 255, 255);
const TAB_INACTIVE_FG: PackedRgba = PackedRgba::rgb(140, 150, 170);
const TAB_KEY_FG: PackedRgba = PackedRgba::rgb(100, 180, 255);

const STATUS_BG: PackedRgba = PackedRgba::rgb(25, 30, 45);
const STATUS_FG: PackedRgba = PackedRgba::rgb(160, 170, 190);
const STATUS_ACCENT: PackedRgba = PackedRgba::rgb(144, 205, 255);
const STATUS_GOOD: PackedRgba = PackedRgba::rgb(120, 220, 150);
const STATUS_WARN: PackedRgba = PackedRgba::rgb(255, 184, 108);

const HELP_BG: PackedRgba = PackedRgba::rgb(20, 24, 38);
const HELP_FG: PackedRgba = PackedRgba::rgb(200, 210, 230);
const HELP_KEY_FG: PackedRgba = PackedRgba::rgb(100, 180, 255);
const HELP_BORDER_FG: PackedRgba = PackedRgba::rgb(80, 100, 140);
const HELP_CATEGORY_FG: PackedRgba = PackedRgba::rgb(180, 140, 255);

// ──────────────────────────────────────────────────────────────────────
// Chrome layout
// ──────────────────────────────────────────────────────────────────────

/// Split the terminal area into tab bar, content, and status line regions.
#[must_use]
pub fn chrome_layout(area: Rect) -> ChromeAreas {
    let chunks = Flex::vertical()
        .constraints([
            Constraint::Fixed(1),
            Constraint::Min(1),
            Constraint::Fixed(1),
        ])
        .split(area);
    ChromeAreas {
        tab_bar: chunks[0],
        content: chunks[1],
        status_line: chunks[2],
    }
}

/// The three regions of the chrome layout.
pub struct ChromeAreas {
    pub tab_bar: Rect,
    pub content: Rect,
    pub status_line: Rect,
}

// ──────────────────────────────────────────────────────────────────────
// Tab bar
// ──────────────────────────────────────────────────────────────────────

/// Render the tab bar into a 1-row area.
pub fn render_tab_bar(active: MailScreenId, frame: &mut Frame, area: Rect) {
    use ftui::text::{Line, Span, Text};

    // Fill background
    let bg_style = Style::default().bg(TAB_INACTIVE_BG);
    Paragraph::new("").style(bg_style).render(area, frame);

    let mut x = area.x;
    let available = area.width;

    // Determine if we need compact mode (< 60 cols)
    let compact = available < 60;

    for (i, meta) in MAIL_SCREEN_REGISTRY.iter().enumerate() {
        let number = i + 1;
        let label = if compact {
            meta.short_label
        } else {
            meta.title
        };
        let is_active = meta.id == active;

        // " 1:Label " — each tab has fixed structure
        let key_str = format!("{number}");
        // Width: space + key + colon + label + space
        let tab_width = u16::try_from(1 + key_str.len() + 1 + label.len() + 1).unwrap_or(u16::MAX);

        if x + tab_width > area.x + available {
            break; // Don't overflow
        }

        let (fg, bg) = if is_active {
            (TAB_ACTIVE_FG, TAB_ACTIVE_BG)
        } else {
            (TAB_INACTIVE_FG, TAB_INACTIVE_BG)
        };

        let spans = vec![
            Span::styled(" ", Style::default().bg(bg)),
            Span::styled(key_str, Style::default().fg(TAB_KEY_FG).bg(bg)),
            Span::styled(":", Style::default().fg(TAB_INACTIVE_FG).bg(bg)),
            Span::styled(label, Style::default().fg(fg).bg(bg)),
            Span::styled(" ", Style::default().bg(bg)),
        ];

        let line = Line::from_spans(spans);
        let tab_area = Rect::new(x, area.y, tab_width, 1);
        Paragraph::new(Text::from_lines([line])).render(tab_area, frame);

        x += tab_width;
    }
}

// ──────────────────────────────────────────────────────────────────────
// Status line
// ──────────────────────────────────────────────────────────────────────

/// Render the status line into a 1-row area.
pub fn render_status_line(
    state: &TuiSharedState,
    active: MailScreenId,
    help_visible: bool,
    frame: &mut Frame,
    area: Rect,
) {
    use ftui::text::{Line, Span, Text};

    // Fill background
    let bg = Style::default().bg(STATUS_BG);
    Paragraph::new("").style(bg).render(area, frame);

    let counters = state.request_counters();
    let uptime = state.uptime();
    let meta = screen_meta(active);

    // Build left section
    let uptime_secs = uptime.as_secs();
    let hours = uptime_secs / 3600;
    let mins = (uptime_secs % 3600) / 60;
    let secs = uptime_secs % 60;
    let uptime_str = if hours > 0 {
        format!("{hours}h{mins:02}m")
    } else {
        format!("{mins}m{secs:02}s")
    };

    // Build center section (live counters)
    let avg_latency = state.avg_latency_ms();
    let error_count = counters.status_4xx + counters.status_5xx;
    let total = counters.total;
    let ok = counters.status_2xx;
    let center_str = format!("req:{total} ok:{ok} err:{error_count} avg:{avg_latency}ms");

    // Build right section
    let help_hint = if help_visible { "[?] Help" } else { "? help" };

    // Calculate widths
    let title = meta.title;
    let left_len = u16::try_from(1 + title.len() + 6 + uptime_str.len() + 1).unwrap_or(u16::MAX);
    let center_len = u16::try_from(center_str.len()).unwrap_or(u16::MAX);
    let right_len = u16::try_from(1 + help_hint.len() + 1).unwrap_or(u16::MAX);
    let total_len = left_len
        .saturating_add(center_len)
        .saturating_add(right_len);
    let available = area.width;

    // Build spans
    let mut spans = Vec::with_capacity(8);

    // Left: screen name + uptime
    spans.push(Span::styled(" ", Style::default().bg(STATUS_BG)));
    spans.push(Span::styled(
        title,
        Style::default().fg(STATUS_ACCENT).bg(STATUS_BG).bold(),
    ));
    spans.push(Span::styled(
        format!(" | up:{uptime_str} "),
        Style::default().fg(STATUS_FG).bg(STATUS_BG),
    ));

    // Center padding + counters
    if total_len < available {
        let pad = (available - total_len) / 2;
        if pad > 0 {
            spans.push(Span::styled(
                " ".repeat(pad as usize),
                Style::default().bg(STATUS_BG),
            ));
        }
    }

    let counter_fg = if error_count > 0 {
        STATUS_WARN
    } else {
        STATUS_GOOD
    };
    spans.push(Span::styled(
        center_str,
        Style::default().fg(counter_fg).bg(STATUS_BG),
    ));

    // Right padding + help hint
    if total_len < available {
        let used_with_center_pad = total_len + (available - total_len) / 2;
        let right_pad = available.saturating_sub(used_with_center_pad);
        if right_pad > 0 {
            spans.push(Span::styled(
                " ".repeat(right_pad as usize),
                Style::default().bg(STATUS_BG),
            ));
        }
    }

    spans.push(Span::styled(
        help_hint,
        Style::default().fg(TAB_KEY_FG).bg(STATUS_BG),
    ));
    spans.push(Span::styled(" ", Style::default().bg(STATUS_BG)));

    let line = Line::from_spans(spans);
    Paragraph::new(Text::from_lines([line])).render(area, frame);
}

// ──────────────────────────────────────────────────────────────────────
// Help overlay
// ──────────────────────────────────────────────────────────────────────

/// Global keybindings shown in every help overlay.
const GLOBAL_KEYBINDINGS: &[(&str, &str)] = &[
    ("1-7", "Jump to screen"),
    ("Tab", "Next screen"),
    ("Shift+Tab", "Previous screen"),
    ("Ctrl+P / :", "Command palette"),
    ("?", "Toggle help"),
    ("q", "Quit"),
    ("Esc", "Dismiss overlay"),
];

/// Render the help overlay centered on the terminal.
pub fn render_help_overlay(
    active: MailScreenId,
    screen_bindings: &[HelpEntry],
    frame: &mut Frame,
    area: Rect,
) {
    // Calculate overlay dimensions (60% width, 60% height, clamped)
    let overlay_width = (u32::from(area.width) * 60 / 100).clamp(36, 72) as u16;
    let overlay_height = (u32::from(area.height) * 60 / 100).clamp(10, 24) as u16;
    let overlay_width = overlay_width.min(area.width.saturating_sub(2));
    let overlay_height = overlay_height.min(area.height.saturating_sub(2));

    // Center the overlay
    let x = area.x + (area.width.saturating_sub(overlay_width)) / 2;
    let y = area.y + (area.height.saturating_sub(overlay_height)) / 2;
    let overlay_area = Rect::new(x, y, overlay_width, overlay_height);

    // Render border frame
    let block = Block::bordered()
        .border_type(BorderType::Double)
        .title(" Keyboard Shortcuts (Esc to close) ")
        .style(Style::default().fg(HELP_BORDER_FG).bg(HELP_BG));

    let inner = block.inner(overlay_area);
    block.render(overlay_area, frame);

    // Render keybinding entries inside the inner area
    let mut y_offset = 0u16;
    let col_width = inner.width.saturating_sub(1);
    let key_col = 14u16; // width for key column

    // Global section header
    if y_offset < inner.height {
        let header = Paragraph::new("Global")
            .style(Style::default().fg(HELP_CATEGORY_FG).bg(HELP_BG).bold());
        header.render(
            Rect::new(inner.x + 1, inner.y + y_offset, col_width, 1),
            frame,
        );
        y_offset += 1;
    }

    // Global keybindings
    for &(key, action) in GLOBAL_KEYBINDINGS {
        if y_offset >= inner.height {
            break;
        }
        render_keybinding_line(
            key,
            action,
            inner.x + 1,
            inner.y + y_offset,
            col_width,
            key_col,
            frame,
        );
        y_offset += 1;
    }

    // Screen-specific section
    if !screen_bindings.is_empty() && y_offset < inner.height {
        // Blank separator
        y_offset += 1;

        let meta = screen_meta(active);
        if y_offset < inner.height {
            let header = Paragraph::new(meta.title)
                .style(Style::default().fg(HELP_CATEGORY_FG).bg(HELP_BG).bold());
            header.render(
                Rect::new(inner.x + 1, inner.y + y_offset, col_width, 1),
                frame,
            );
            y_offset += 1;
        }

        for entry in screen_bindings {
            if y_offset >= inner.height {
                break;
            }
            render_keybinding_line(
                entry.key,
                entry.action,
                inner.x + 1,
                inner.y + y_offset,
                col_width,
                key_col,
                frame,
            );
            y_offset += 1;
        }
    }
}

/// Render a single keybinding line: `  [key]  action`
fn render_keybinding_line(
    key: &str,
    action: &str,
    x: u16,
    y: u16,
    width: u16,
    key_col: u16,
    frame: &mut Frame,
) {
    use ftui::text::{Line, Span, Text};

    let key_display = format!("  [{key}]");
    let key_len = u16::try_from(key_display.len()).unwrap_or(key_col);
    let pad_len = key_col.saturating_sub(key_len) as usize;
    let padding = " ".repeat(pad_len);

    let spans = vec![
        Span::styled(key_display, Style::default().fg(HELP_KEY_FG).bg(HELP_BG)),
        Span::styled(padding, Style::default().bg(HELP_BG)),
        Span::styled(action, Style::default().fg(HELP_FG).bg(HELP_BG)),
    ];

    let line = Line::from_spans(spans);
    let area = Rect::new(x, y, width, 1);
    Paragraph::new(Text::from_lines([line])).render(area, frame);
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui_screens::ALL_SCREEN_IDS;

    #[test]
    fn chrome_layout_splits_correctly() {
        let area = Rect::new(0, 0, 80, 24);
        let chrome = chrome_layout(area);
        assert_eq!(chrome.tab_bar.height, 1);
        assert_eq!(chrome.status_line.height, 1);
        assert_eq!(chrome.content.height, 22); // 24 - 1 - 1
        assert_eq!(chrome.tab_bar.y, 0);
        assert_eq!(chrome.content.y, 1);
        assert_eq!(chrome.status_line.y, 23);
    }

    #[test]
    fn chrome_layout_minimum_height() {
        let area = Rect::new(0, 0, 80, 3);
        let chrome = chrome_layout(area);
        assert_eq!(chrome.tab_bar.height, 1);
        assert_eq!(chrome.content.height, 1);
        assert_eq!(chrome.status_line.height, 1);
    }

    #[test]
    fn global_keybindings_complete() {
        assert!(GLOBAL_KEYBINDINGS.len() >= 5);
        for &(key, action) in GLOBAL_KEYBINDINGS {
            assert!(!key.is_empty());
            assert!(!action.is_empty());
        }
    }

    #[test]
    fn tab_count_matches_screens() {
        assert_eq!(MAIL_SCREEN_REGISTRY.len(), ALL_SCREEN_IDS.len());
        assert_eq!(MAIL_SCREEN_REGISTRY.len(), 7);
    }

    #[test]
    fn color_constants_are_valid() {
        let colors = [
            TAB_ACTIVE_BG,
            TAB_INACTIVE_BG,
            STATUS_BG,
            HELP_BG,
            STATUS_ACCENT,
        ];
        for color in colors {
            assert_ne!(color, PackedRgba::rgba(0, 0, 0, 0));
        }
    }

    #[test]
    fn screen_meta_for_all_ids() {
        for &id in ALL_SCREEN_IDS {
            let meta = screen_meta(id);
            assert!(!meta.title.is_empty());
            assert!(!meta.short_label.is_empty());
            assert!(meta.short_label.len() <= 12);
        }
    }
}
